/*
 * Haiku's USBKit backend for libusb 1.0
 * Copyright (C) 2010-2011 Philippe Houdoin <phoudoin +at+ haiku-os +dot+ org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <config.h>
#include <ctype.h>
// #include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <unistd.h>
// #include <time.h>

#include <Autolock.h>
#include <List.h>
#include <Locker.h>
#include <OS.h>
#include <Path.h>
#include <String.h>
#include <USBKit.h>

#include "libusbi.h"


#define TRACE 1
// #undef TRACE

const char* kBusRootPath = "/dev/bus/usb";

class UsbDeviceInfo;
class UsbDeviceHandle;
class UsbTransfer;


class UsbDeviceInfo {
public:
										UsbDeviceInfo(BUSBDevice* usbkit_device);
	virtual								~UsbDeviceInfo();

	void								Get();
	void								Put();

	const char*							Location() const;
	const usb_device_descriptor*		Descriptor() const;
	uint32								CountConfigurations() const;
	const usb_configuration_descriptor*	ConfigurationDescriptorAt(uint32 index) const;
	void								SetActiveConfiguration(uint32 index);
	uint32								ActiveConfiguration() const;

private:
	usb_device_descriptor				fDeviceDescriptor;
	usb_configuration_descriptor**		fConfigurationDescriptors;
	uint32								fActiveConfiguration;
	char*								fPath;
	volatile int32						fOpenCount;
};


class UsbTransfer {
public:
							UsbTransfer(struct usbi_transfer* itransfer);
	virtual					~UsbTransfer();

			
	int 					Submit();
	int 					Cancel();
	void 					Do();
	
private:
	struct usbi_transfer*	fUsbiTransfer;
	struct libusb_transfer*	fLibusbTransfer;
	UsbDeviceHandle*		fDeviceHandle;
	BUSBEndpoint*			fEndpoint;
};


class UsbDeviceHandle {
public:
					UsbDeviceHandle(UsbDeviceInfo* usbDeviceInfo);
	virtual			~UsbDeviceHandle();

	UsbDeviceInfo*	Info() 		{ return fDeviceInfo; }
	BUSBDevice*		Device() 	{ return fDevice; }

	int				EventPipe(int index) const;

	status_t		ClearStallEndpoint(int endpoint);
	status_t		ResetDevice();

	status_t		SubmitTransfer(UsbTransfer* transfer);
	status_t		CancelTransfer(UsbTransfer* transfer);

private:
	static status_t	_TransfersThread(void *self);
	void			_TransfersWorker();

	UsbDeviceInfo*	fDeviceInfo;
	BUSBDevice*		fDevice;
	int				fEventPipes[2];
	BLocker			fTransfersLock;
	BList			fTransfers;
	sem_id			fTransfersSem;
	thread_id		fTransfersThread;
	UsbTransfer* 	fPendingTransfer;
};



// #pragma mark - UsbDeviceInfo class


UsbDeviceInfo::UsbDeviceInfo(BUSBDevice* usbkit_device)
	: 	fPath(NULL),
		fConfigurationDescriptors(NULL),
		fActiveConfiguration(0),
		fOpenCount(0)
{
	memset(&fDeviceDescriptor, 0, sizeof(fDeviceDescriptor));

	if (!usbkit_device)
		return;

	// Cache device descriptor
	memcpy(&fDeviceDescriptor, usbkit_device->Descriptor(), sizeof(fDeviceDescriptor));
	fPath = strdup(usbkit_device->Location());

	// Cache all device configuration(s) complete descriptor(s)
	fConfigurationDescriptors = new usb_configuration_descriptor*[CountConfigurations()];
	if (!fConfigurationDescriptors)
		return;

	for (uint32 i = 0; i < CountConfigurations(); i++) {
		const BUSBConfiguration* configuration = usbkit_device->ConfigurationAt(i);
		const usb_configuration_descriptor* descriptor = NULL;
		if (configuration != NULL)
			descriptor = configuration->Descriptor();
			
		if (descriptor != NULL) {
			fConfigurationDescriptors[i]
				= (usb_configuration_descriptor*)malloc(descriptor->total_length);
			if (fConfigurationDescriptors[i] != NULL) {
				size_t size = usbkit_device->GetDescriptor(USB_DESCRIPTOR_CONFIGURATION,
					i, 0, fConfigurationDescriptors[i], descriptor->total_length);
			}
		} else
			fConfigurationDescriptors[i] = NULL;
	}
			
	// Cache active configuration index
	fActiveConfiguration = usbkit_device->ActiveConfiguration()->Index();
}



UsbDeviceInfo::~UsbDeviceInfo()
{
	free(fPath);

	memset(&fDeviceDescriptor, 0, sizeof(fDeviceDescriptor));

	for (uint32 i = 0; i < CountConfigurations(); i++) {
		if (fConfigurationDescriptors[i])
			free(fConfigurationDescriptors[i]);
	}

	delete[] fConfigurationDescriptors;

}


inline void
UsbDeviceInfo::Get()
{
	atomic_add(&fOpenCount, 1);
}


inline void
UsbDeviceInfo::Put()
{
	if (atomic_add(&fOpenCount, -1) == 1)
		delete this;
}


inline const char*
UsbDeviceInfo::Location() const
{
	return fPath;
}


inline const usb_device_descriptor*
UsbDeviceInfo::Descriptor() const
{
	return &fDeviceDescriptor;
}


inline uint32
UsbDeviceInfo::CountConfigurations() const
{
	return fDeviceDescriptor.num_configurations;
}


const usb_configuration_descriptor*
UsbDeviceInfo::ConfigurationDescriptorAt(uint32 index) const
{
	if (index >= CountConfigurations())
		return NULL;

	return fConfigurationDescriptors[index];
}


inline uint32
UsbDeviceInfo::ActiveConfiguration() const
{
	return fActiveConfiguration;
}


//  #pragma mark - UsbDeviceHandle class


UsbDeviceHandle::UsbDeviceHandle(UsbDeviceInfo* deviceInfo)
	: 
	fDeviceInfo(deviceInfo),
	fTransfersThread(-1)
{
	fDeviceInfo->Get();

	BString devicePath = kBusRootPath;
	devicePath += deviceInfo->Location();
	fDevice = new BUSBDevice(devicePath);

	// Create pipe used for asynchronous event polling
	pipe(fEventPipes);

  	// set the write pipe to be non-blocking
	fcntl(fEventPipes[1], F_SETFD, O_NONBLOCK);
	
	fTransfersSem = create_sem(0, "Transfers queue sem");
}


UsbDeviceHandle::~UsbDeviceHandle()
{
	close(fEventPipes[1]);
	close(fEventPipes[0]);

	delete_sem(fTransfersSem);
	if (fTransfersThread > 0)
		wait_for_thread(fTransfersThread, NULL);

	delete fDevice;

	fDeviceInfo->Put();
}

int
UsbDeviceHandle::EventPipe(int index) const
{
	if (index < 0 || index > 1)
		return -1;
	return fEventPipes[index];
}


status_t
UsbDeviceHandle::ClearStallEndpoint(int endpoint)
{
	// TODO
	return B_OK;
}


status_t
UsbDeviceHandle::ResetDevice()
{
	// TODO
	return B_OK;
}


status_t
UsbDeviceHandle::SubmitTransfer(UsbTransfer* transfer)
{
	BAutolock locker(fTransfersLock);
	fTransfers.AddItem(transfer);

	// wakeup Transfers worker thread	
	release_sem(fTransfersSem);
}


status_t
UsbDeviceHandle::CancelTransfer(UsbTransfer* transfer)
{
	fTransfersLock.Lock();
	bool removed = fTransfers.RemoveItem(transfer);
	fTransfersLock.Unlock();
	
	if (removed)
		return B_OK;
		
/*
	if (fPendingTransfer == transfer) {
		// signal the worker thread to interrupt the pending transfer
	}
*/
	return B_OK;
}


/*static*/ status_t
UsbDeviceHandle::_TransfersThread(void* self)
{
	((UsbDeviceHandle*)self)->_TransfersWorker();
	return B_OK;
}


void
UsbDeviceHandle::_TransfersWorker()
{
	while (true) {
		status_t status = acquire_sem(fTransfersSem);
		if (status == B_OK || status == B_BAD_SEM_ID)
			break;
		if (status == B_INTERRUPTED)
			continue;

		fTransfersLock.Lock();
		fPendingTransfer = (UsbTransfer*)fTransfers.RemoveItem((int32) 0);
		fTransfersLock.Unlock();
		
		if (!fPendingTransfer)	// Doh!
			continue;
			
		fPendingTransfer->Do();
		fPendingTransfer = NULL;	
		
		// the actual UsbTransfer object deletion is done 
		// at libusb's internal transfer deletion.
		// See haiku_clear_transfer_priv()
	}
}


//  #pragma mark - UsbTranfer class


UsbTransfer::UsbTransfer(struct usbi_transfer* itransfer)
	: fUsbiTransfer(itransfer)
{
	fLibusbTransfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
	fDeviceHandle = *((UsbDeviceHandle**)fLibusbTransfer->dev_handle->os_priv);
}


UsbTransfer::~UsbTransfer()
{
}


int
UsbTransfer::Submit()
{
	fDeviceHandle->SubmitTransfer(this);
	return LIBUSB_ERROR_INVALID_PARAM;
}


int
UsbTransfer::Cancel()
{
	// TODO
	return LIBUSB_ERROR_INVALID_PARAM;
}


void
UsbTransfer::Do()
{
	switch (fLibusbTransfer->type) {
	case LIBUSB_TRANSFER_TYPE_CONTROL: {
		struct libusb_control_setup* setup 
			= (struct libusb_control_setup*)fLibusbTransfer->buffer;
			
		ssize_t size = fDeviceHandle->Device()->ControlTransfer(
			setup->bmRequestType, setup->bRequest, 
			setup->wValue, setup->wIndex, setup->wLength, 
			fLibusbTransfer->buffer + LIBUSB_CONTROL_SETUP_SIZE);
		break;
	}
	case LIBUSB_TRANSFER_TYPE_BULK:
	case LIBUSB_TRANSFER_TYPE_INTERRUPT: {
		// fDeviceHandle->SubmitBulkTransfer(itransfer);
	}
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: {
		// fDeviceHandle->SubmitIsochronousTransfer(itransfer);
	}
	default:
		usbi_err(TRANSFER_CTX(fLibusbTransfer), "unknown endpoint type %d", 
			fLibusbTransfer->type);
	}
}


//  #pragma mark - UsbRoster class

class UsbRoster : public BUSBRoster {
public:
                   UsbRoster()  {}

	virtual status_t    DeviceAdded(BUSBDevice* device);
	virtual void        DeviceRemoved(BUSBDevice* device);

private:
	status_t			_AddNewDevice(struct libusb_context* ctx, UsbDeviceInfo* info);
	
	BLocker	fDevicesLock;
	BList	fDevices;
};


status_t
UsbRoster::_AddNewDevice(struct libusb_context* ctx, UsbDeviceInfo* deviceInfo)
{
	struct libusb_device* dev = usbi_get_device_by_session_id(ctx, (unsigned long)deviceInfo);
	if (dev) {
		usbi_info (ctx, "using existing device for location ID 0x%08x", deviceInfo);
	} else {
		usbi_info (ctx, "allocating new device for session ID 0x%08x", deviceInfo);
		dev = usbi_alloc_device(ctx, (unsigned long)deviceInfo);
		if (!dev) {
			return B_NO_MEMORY;
		}
		*((UsbDeviceInfo**)dev->os_priv) = deviceInfo;

		// TODO: handle device address mapping for devices in non-root hub(s)
		sscanf(deviceInfo->Location(), "/%d/%d", &dev->bus_number, &dev->device_address);
		dev->num_configurations = (uint8_t) deviceInfo->CountConfigurations();

		// printf("bus %d, address %d, # of configs %d\n", dev->bus_number,
		//	dev->device_address, dev->num_configurations);

    	if(usbi_sanitize_device(dev) < 0) {
			libusb_unref_device(dev);
			return B_ERROR;	
		}
	}

    usbi_connect_device (dev);
   	return B_OK;
}


status_t
UsbRoster::DeviceAdded(BUSBDevice* device)
{
#if TRACE
	printf("UsbRoster::DeviceAdded(BUSBDevice %p: %s%s)\n", device, kBusRootPath, 
		device->Location());
#endif
 
 	if (device->IsHub())
 		return B_ERROR;
 
	UsbDeviceInfo* deviceInfo = new UsbDeviceInfo(device);
	deviceInfo->Get();
	
	// Add this new device to each active context's device list
	struct libusb_context *ctx;
	usbi_mutex_lock(&active_contexts_lock);
	list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) {
		// printf("UsbRoster::DeviceAdded() active_contexts_list: ctx %p\n", ctx); 
		_AddNewDevice(ctx, deviceInfo);
	}
	usbi_mutex_unlock(&active_contexts_lock);

	BAutolock locker(fDevicesLock);
	fDevices.AddItem(deviceInfo);
	
	return B_OK;
}


void
UsbRoster::DeviceRemoved(BUSBDevice* device)
{
#if TRACE
	printf("UsbRoster::DeviceRemoved(BUSBDevice %p: %s%s)\n", device, kBusRootPath, 
		device->Location());
#endif

	BAutolock locker(fDevicesLock);
	UsbDeviceInfo* deviceInfo;
	int i = 0;
	while (deviceInfo = (UsbDeviceInfo*)fDevices.ItemAt(i++)) {
		if (!deviceInfo)
			continue;

		if (strcmp(deviceInfo->Location(), device->Location()) == 0)
			break;
	}

	if (!deviceInfo)
		return;

	// Remove this device from each active context's device list 
	struct libusb_context *ctx;
	struct libusb_device *dev;
	
	usbi_mutex_lock(&active_contexts_lock);
	list_for_each_entry(ctx, &active_contexts_list, list, struct libusb_context) {
		dev = usbi_get_device_by_session_id (ctx, (unsigned long)deviceInfo);
		if (dev != NULL) {
			usbi_disconnect_device (dev);
		}
	}
	usbi_mutex_static_unlock(&active_contexts_lock);

	fDevices.RemoveItem(deviceInfo);
	deviceInfo->Put();
}


//  #pragma mark - libusb Haiku backend

// Context


UsbRoster 		gUsbRoster;
volatile int32	gInitCount = 0;

static int
haiku_init(struct libusb_context* ctx)
{
	if (atomic_add(&gInitCount, 1) == 0)
		gUsbRoster.Start();
	return 0;
}


static void
haiku_exit(void)
{
	if (atomic_add(&gInitCount, -1) == 1)
		gUsbRoster.Stop();
}


static int
haiku_handle_events(struct libusb_context* ctx, struct pollfd* fds, nfds_t nfds, int num_ready)
{
	int status;

	pthread_mutex_lock(&ctx->open_devs_lock);

	for (int i = 0; i < nfds && num_ready > 0; i++) {
		struct pollfd *pollfd = &fds[i];
		struct libusb_device_handle *handle;
		UsbDeviceHandle* deviceHandle = NULL;

		if (!pollfd->revents)
			continue;

		num_ready--;
		list_for_each_entry(handle, &ctx->open_devs, list, struct libusb_device_handle) {
			deviceHandle = *((UsbDeviceHandle**)handle->os_priv);
			if (deviceHandle->EventPipe(0) == pollfd->fd)
				// Found source deviceHandle
				break;
		}

		if (pollfd->revents & POLLERR) {
			usbi_remove_pollfd(HANDLE_CTX(handle), deviceHandle->EventPipe(0));
			usbi_handle_disconnect(handle);
			continue;
		}

		// TODO: read message from pipe, and handle it:
		// transfer completion message or device gone message?
	}

	status = 0;
out:
	pthread_mutex_unlock(&ctx->open_devs_lock);
	return status;
}


// Device query


static int
haiku_get_device_descriptor(struct libusb_device* dev, unsigned char* buffer, int* host_endian)
{
	UsbDeviceInfo* deviceInfo = *((UsbDeviceInfo**)dev->os_priv);
	if (!deviceInfo)
		return LIBUSB_ERROR_INVALID_PARAM;

	// return cached copy
	memcpy(buffer, deviceInfo->Descriptor(), DEVICE_DESC_LENGTH);

	*host_endian = 0;
	return 0;
}


static int
haiku_get_config_descriptor(struct libusb_device* dev, uint8_t config_index,
	unsigned char* buffer, size_t len, int* host_endian)
{
	UsbDeviceInfo* deviceInfo = *((UsbDeviceInfo**)dev->os_priv);
	if (!deviceInfo)
		return LIBUSB_ERROR_INVALID_PARAM;

	// return cached configuration
	const usb_configuration_descriptor* descriptor
		= deviceInfo->ConfigurationDescriptorAt(config_index);
	if (!descriptor)
		return LIBUSB_ERROR_INVALID_PARAM;

	// TODO: assemble the config desc from device, interfaces and endpoints desc
	if (len > descriptor->total_length)
		len = descriptor->total_length;
	memcpy(buffer, descriptor, len);

	*host_endian = 0;
	return 0;
}


static int
haiku_get_active_config_descriptor(struct libusb_device* dev,
	unsigned char* buffer, size_t len, int* host_endian)
{
	UsbDeviceInfo* deviceInfo = *((UsbDeviceInfo**)dev->os_priv);
	if (!deviceInfo)
		return LIBUSB_ERROR_INVALID_PARAM;

	return haiku_get_config_descriptor(dev, deviceInfo->ActiveConfiguration(),
		buffer, len, host_endian);
}


void
haiku_destroy_device(struct libusb_device* dev)
{
	UsbDeviceInfo* deviceInfo = *((UsbDeviceInfo**)dev->os_priv);
	deviceInfo->Put();
	*((UsbDeviceInfo**)dev->os_priv) = NULL;

}
 

// #pragma mark -----

static int
haiku_open_device(struct libusb_device_handle *dev_handle)
{
	UsbDeviceInfo* deviceInfo = *((UsbDeviceInfo**)dev_handle->dev->os_priv);
	UsbDeviceHandle* deviceHandle = new UsbDeviceHandle(deviceInfo);

	*((UsbDeviceHandle**)dev_handle->os_priv) = deviceHandle;

	// register its event pipe
	usbi_add_pollfd(HANDLE_CTX(dev_handle), deviceHandle->EventPipe(0), POLLIN);

	usbi_info(HANDLE_CTX(dev_handle), "Device open for access");
	return 0;
}


static void
haiku_close_device(struct libusb_device_handle* dev_handle)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return;

	// make sure all interfaces are released
	for (int i = 0 ; i < USB_MAXINTERFACES ; i++) {
    	if (dev_handle->claimed_interfaces & (1 << i))
      		libusb_release_interface(dev_handle, i);
	}

	// unregister its event pipe
	usbi_remove_pollfd(HANDLE_CTX(dev_handle), deviceHandle->EventPipe(0));

	delete deviceHandle;
	*((UsbDeviceHandle**)dev_handle->os_priv) = NULL;
}


static int
haiku_get_configuration(struct libusb_device_handle* dev_handle, int* config)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	*config = deviceHandle->Info()->ActiveConfiguration();
	return 0;
}


static int
haiku_set_configuration(struct libusb_device_handle* dev_handle, int config)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	return 0;
}


static int
haiku_claim_interface(struct libusb_device_handle* dev_handle, int iface)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	// TODO
	return 0;
}


static int
haiku_release_interface(struct libusb_device_handle* dev_handle, int iface)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	// TODO
	return 0;
}


static int
haiku_set_interface_altsetting(struct libusb_device_handle* dev_handle,
	int iface, int altsetting)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	// TODO
	return 0;
}


static int
haiku_clear_halt(struct libusb_device_handle* dev_handle, unsigned char endpoint)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	deviceHandle->ClearStallEndpoint(endpoint);
	return 0;
}


static int
haiku_reset_device(struct libusb_device_handle* dev_handle)
{
	UsbDeviceHandle* deviceHandle = *((UsbDeviceHandle**)dev_handle->os_priv);

	if (deviceHandle == NULL)
		return LIBUSB_ERROR_INVALID_PARAM;

	deviceHandle->ResetDevice();
	return 0;
}


// #pragma mark ----

static int
haiku_submit_transfer(struct usbi_transfer* itransfer)
{
	UsbTransfer* transfer = new UsbTransfer(itransfer);
	*((UsbTransfer**)usbi_transfer_get_os_priv(itransfer)) = transfer;

	return transfer->Submit();
}


static int
haiku_cancel_transfer(struct usbi_transfer* itransfer)
{
	UsbTransfer* transfer = (UsbTransfer*)usbi_transfer_get_os_priv(itransfer);
	return transfer->Cancel();
}


static void
haiku_clear_transfer_priv(struct usbi_transfer* itransfer)
{
	UsbTransfer* transfer = (UsbTransfer*)usbi_transfer_get_os_priv(itransfer);
	delete transfer;

	*((UsbTransfer**)usbi_transfer_get_os_priv(itransfer)) = NULL;
}


//  #pragma mark ----


static int
haiku_clock_gettime(int clk_id, struct timespec *tp)
{
	return LIBUSB_ERROR_INVALID_PARAM;
}


const struct usbi_os_backend haiku_usbkit_backend = {

	/*.name =*/ "Haiku USBKit",
	/*.caps =*/ 0,
	/*.init =*/ haiku_init,
	/*.exit =*/ haiku_exit,
	/*.get_device_list =*/ NULL,
	/*.hotplug_poll =*/ NULL,
	
	/*.open =*/ haiku_open_device,
	/*.close =*/ haiku_close_device,
	/*.get_device_descriptor =*/ haiku_get_device_descriptor,
	/*.get_active_config_descriptor =*/ haiku_get_active_config_descriptor,
	/*.get_config_descriptor =*/ haiku_get_config_descriptor,
	/*.get_config_descriptor_by_value =*/ NULL,

	/*.get_configuration =*/ haiku_get_configuration,
	/*.set_configuration =*/ haiku_set_configuration,
	/*.claim_interface =*/ haiku_claim_interface,
	/*.release_interface =*/ haiku_release_interface,

	/*.set_interface_altsetting =*/ haiku_set_interface_altsetting,
	/*.clear_halt =*/ haiku_clear_halt,
	/*.reset_device =*/ haiku_reset_device,

	/*.kernel_driver_active =*/ NULL,
	/*.detach_kernel_driver =*/ NULL,
	/*.attach_kernel_driver =*/ NULL,

	/*.destroy_device =*/ haiku_destroy_device,

	/*.submit_transfer =*/ haiku_submit_transfer,
	/*.cancel_transfer =*/ haiku_cancel_transfer,
	/*.clear_transfer_priv =*/ haiku_clear_transfer_priv,

	/*.handle_events =*/ haiku_handle_events,

	/*.clock_gettime =*/ haiku_clock_gettime,

	/*.device_priv_size =*/ sizeof(UsbDeviceInfo*),
	/*.device_handle_priv_size =*/ sizeof(UsbDeviceHandle*),
	/*.transfer_priv_size =*/ sizeof(UsbTransfer*),	
	/*.add_iso_packet_size =*/ 0,
};

