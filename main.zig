const std = @import("std");
const windows = std.os.windows;

const BYTE = windows.BYTE; // u8
const WORD = windows.WORD; // u16
const DWORD = windows.DWORD; // u32
const ULONGLONG = windows.ULONGLONG; // u64
const WCHAR = windows.WCHAR;
const HMODULE = windows.HMODULE;
const WINAPI = windows.WINAPI;
const HWND = windows.HWND;
const UINT = windows.UINT;
const INT = windows.INT;
const LPCSTR = windows.LPCSTR;

const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: DWORD,
    Size: DWORD,
};

const IMAGE_NT_HEADERS = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_FILE_HEADER = extern struct {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
};

const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: DWORD,
    TimeDateStamp: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    Name: DWORD,
    Base: DWORD,
    NumberOfFunctions: DWORD,
    NumberOfNames: DWORD,
    AddressOfFunctions: DWORD,
    AddressOfNames: DWORD,
    AddressOfNameOrdinals: DWORD,
};

const IMAGE_DOS_HEADER = extern struct {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [4]WORD,
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [10]WORD,
    e_lfanew: DWORD,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: WORD,
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: ULONGLONG,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeader: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: ULONGLONG,
    SizeOfStackCommit: ULONGLONG,
    SizeOfHeapReserve: ULONGLONG,
    SizeOfHeapCommit: ULONGLONG,
    LoaderFlags: DWORD,
    NumberOfRvaAndSize: DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

fn getKernel32Base() ?*anyopaque {
    const peb = windows.peb();
    var list_entry = peb.Ldr.InMemoryOrderModuleList.Flink;

    while (true) {
        const module: *const windows.LDR_DATA_TABLE_ENTRY = @fieldParentPtr("InMemoryOrderLinks", list_entry);

        if (module.FullDllName.Buffer) |buffer| {
            var dll_name: [256]u8 = undefined;
            var i: usize = 0;

            while (i < module.FullDllName.Length / @sizeOf(WCHAR) and i < 255) {
                dll_name[i] = @truncate(buffer[i]);
                i += 1;
            }

            dll_name[i] = 0;

            if (std.ascii.eqlIgnoreCase(dll_name[0..i], "c:\\windows\\system32\\kernel32.dll")) {
                return module.DllBase;
            }
        }

        list_entry = list_entry.Flink;

        if (list_entry == &peb.Ldr.InMemoryOrderModuleList) break;
    }

    return null;
}

pub fn getProcAddress(base_address: [*]const u8, proc_name: [*:0]const u8) ?*anyopaque {
    const dos_header: *const IMAGE_DOS_HEADER = @alignCast(@ptrCast(base_address));
    const nt_headers: *const IMAGE_NT_HEADERS = @alignCast(@ptrCast(base_address + @as(usize, @intCast(dos_header.e_lfanew))));
    const export_directory_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    const export_directory: *const IMAGE_EXPORT_DIRECTORY = @alignCast(@ptrCast(base_address + @as(usize, export_directory_rva)));
    const address_of_names: [*]const u32 = @alignCast(@ptrCast(base_address + @as(usize, export_directory.AddressOfNames)));
    const address_of_functions: [*]const u32 = @alignCast(@ptrCast(base_address + @as(usize, export_directory.AddressOfFunctions)));
    const address_of_name_ordinals: [*]const u16 = @alignCast(@ptrCast(base_address + @as(usize, export_directory.AddressOfNameOrdinals)));

    for (0..export_directory.NumberOfNames) |i| {
        const name: [*:0]const u8 = @ptrCast(base_address + @as(usize, address_of_names[i]));

        const span = std.mem.span;
        if (std.mem.eql(u8, span(name), span(proc_name))) {
            const ordinal = address_of_name_ordinals[i];
            const function_rva = address_of_functions[ordinal];

            return @as(?*anyopaque, @ptrCast(@constCast(base_address + @as(usize, function_rva))));
        }
    }

    return null;
}

const LoadLibraryAFn = *const fn (lpLibFileName: [*:0]const u8) callconv(WINAPI) ?HMODULE;
const MessageBoxAFn = *const fn (hWnd: ?HWND, lpText: LPCSTR, lpCaption: LPCSTR, UINT) callconv(WINAPI) INT;

pub fn main() !void {
    const kernel32_base = getKernel32Base() orelse return error.FailedToFindKernel32BaseAddress;
    const loadLibrary = @as(LoadLibraryAFn, @ptrCast(getProcAddress(@ptrCast(kernel32_base), "LoadLibraryA") orelse return error.FailedToFindLoadLibraryA));

    const user32 = loadLibrary("user32.dll") orelse return error.FailedToLoadUser32Dll;
    const messageBox = @as(MessageBoxAFn, @ptrCast(getProcAddress(@ptrCast(user32), "MessageBoxA") orelse return error.FailedToLoadMessageBoxA));

    _ = messageBox(null, "the peb has been walked", "<3 ziggooner", 0);
}
