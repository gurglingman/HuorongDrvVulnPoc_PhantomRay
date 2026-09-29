
struct _G_FUNC3{
	void* ctrl1;
	void* ctrl2;
	void* ctrl3;
	void* ctrl4;
	void* ctrl5;
	void* ctrl6;
	void* ctrl7;
	void* ctrl8;
	void* ctrl9;
	void* ctrl10;
	void* ctrl11;
	void* ctrl12;
	void* ctrl13;
	void* ctrl14;
	
};

struct _G_FUNC4{
	void* Registry_Io_dispatch;  // symbolic-link IO control pass-through
	void* UnRegistry_Io; // controls whether an unload handler exists
	LONGLONG isboot; // NULL means re-initialization is required
	void* isCurrentDevice;
	void* Utils_ctr_5[0x10];
};


// singly-linked list node
struct _DEVICE_LIST{
	_DEVICE_LIST* Next;  // NULL terminates the list
	_G_FUNC4* Device_Classobj;
	ULONG Device_bInit; // non-zero when fully initialized
};

#pragma pack(1)
struct _OPEN_PROCESS{
	ULONG64 pid;
	ULONG mask;
	ULONG64 outhandle;
};
#pragma pack()
