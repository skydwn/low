// ============================================================================
// lowdll.cpp — DLL didática
//
// Mensagem exibida: "Injecao realizada com sucesso!"
// Para ofuscação de strings: XOR com chave 0x5A (como no injector)
//
// Compilar: cl /nologo /LD /O2 /MT /W3 lowdll.cpp /link /OUT:lowdll.dll
// ============================================================================
#include <windows.h>
#include <stdint.h>

// XOR para decodificar a mensagem de demonstração
template <size_t N>
struct XorMsg {
    unsigned char enc[N];
    unsigned char key;
    constexpr XorMsg(const char (&s)[N], unsigned char k) : enc{}, key(k) {
        for (size_t i = 0; i < N; i++)
            enc[i] = (unsigned char)s[i] ^ k;
    }
    void decrypt(char* out) const {
        for (size_t i = 0; i < N; i++)
            out[i] = (char)(enc[i] ^ key);
    }
};

// Texto puro passado ao construtor (chave 0x5A): o compilador cifra em tempo
// de compilação, então só os bytes XOR ficam na .rdata da DLL.
static constexpr XorMsg<31> ENC_MSG("Injecao realizada com sucesso!", 0x5A);

static void show_message(void) {
    char buf[31];
    ENC_MSG.decrypt(buf);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w = 0;
    if (hOut && hOut != INVALID_HANDLE_VALUE)
        WriteFile(hOut, buf, (DWORD)(30), &w, NULL);
}

// ============================================================================
// Entrypoint da DLL
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved) {
    (void)hMod; (void)lpReserved;
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Evita deadlocks/threading desnecessários em alguns casos didáticos
        show_message();
    }
    return TRUE;
}
