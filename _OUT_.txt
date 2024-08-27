// not 4 overload names
FARPROC GetProcAddressNoExternCExport(HMODULE hModule, LPCSTR lpProcName)
{
#define INRANGE(x,a,b) (x >= a && x <= b)
#define getBits( x ) (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x ) (getBits(x[0]) << 4 | getBits(x[1]))

	if (!hModule || !lpProcName) { return NULL; }
	MODULEINFO modInfo = { 0 };
	size_t sz = strlen(lpProcName);
	//printf("%d\n", sz);
	// get bounds searching
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) { return NULL; }
	// mk pattern from str
	char* pattern = (char*)malloc(sz * 3); // last space \0
	if (!pattern) { return NULL; }
	for (size_t i = 0; i < sz; ++i) { sprintf(pattern + (3 * i), "%02x ", (unsigned char)lpProcName[i]); }
	pattern[sz * 3] = 0; // sz
	//printf("%s\n", pattern); // sprintf buff
	// scan mem
	char* buffptr_pattern = pattern;
	uintptr_t pMatch = 0;
	for (uintptr_t MemPtr = (uintptr_t)hModule; MemPtr < ((uintptr_t)hModule + modInfo.SizeOfImage); MemPtr++)
	{
		if (!*buffptr_pattern) { break; }
		if (*(PBYTE)buffptr_pattern == '\?' || *(BYTE*)MemPtr == getByte(buffptr_pattern))
		{
			if (!pMatch) { pMatch = MemPtr; }
			if (!buffptr_pattern[2]) { break; } // паттерн закончился
			//PWORD первых 2 символа из паттерна, PBYTE первый символ
			if (*(PWORD)buffptr_pattern == '\?\?' || *(PBYTE)buffptr_pattern != '\?') { buffptr_pattern += 3; }
			else { buffptr_pattern += 2; } //one ?
		}
		else
		{ // срыв совпадения
			buffptr_pattern = pattern;
			if (pMatch) { MemPtr = pMatch; }
			pMatch = 0;
		}
	}
	free(pattern);
	if (!pMatch || (*((char*)pMatch - 1) != '?')) { return NULL; }
	//printf("found str: 0x%p\n", (char*)pMatch - 1);
	return GetProcAddress(hModule, (char*)pMatch - 1); // ? перед name
#undef getByte;
#undef getByte;
#undef INRANGE;
}

FARPROC GetProcAddressNoExternCExportLDFile(HMODULE hModule, LPCSTR lpProcName)
{
#define INRANGE(x,a,b) (x >= a && x <= b)
#define getBits( x ) (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x ) (getBits(x[0]) << 4 | getBits(x[1]))

	if (!hModule || !lpProcName) { return NULL; }
	size_t sz = strlen(lpProcName);
	// get file path
	char path[MAX_PATH]; // not need free
	if (!GetModuleFileName(hModule, path, MAX_PATH)) { return NULL; }
	// load hModule into ram as file
	FILE* file = fopen(path, "rb");
	if (!file) { return NULL; }
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file); // 2 start
	void* buff = malloc(fileSize);
	if (!buff) { return NULL; }
	fread(buff, sizeof(char), fileSize, file);
	fclose(file);
	file = NULL;
	//printf("buff: 0x%p\n", buff);
	//printf("size buff: %zu\n", fileSize);
	// mk pattern from str
	char* pattern = (char*)malloc(sz * 3); // last space \0
	if (!pattern) { return NULL; }
	for (size_t i = 0; i < sz; ++i) { sprintf(pattern + (3 * i), "%02x ", (unsigned char)lpProcName[i]); }
	pattern[sz * 3] = 0; // sz
	//printf("%s\n", pattern); // sprintf buff
	// scan mem
	char* buffptr_pattern = pattern;
	uintptr_t pMatch = 0;
	for (uintptr_t MemPtr = (uintptr_t)buff; MemPtr < ((uintptr_t)buff + fileSize); MemPtr++)
	{
		if (!*buffptr_pattern) { break; }
		if (*(PBYTE)buffptr_pattern == '\?' || *(BYTE*)MemPtr == getByte(buffptr_pattern))
		{
			if (!pMatch) { pMatch = MemPtr; }
			if (!buffptr_pattern[2]) { break; } // паттерн закончился
			//PWORD первых 2 символа из паттерна, PBYTE первый символ
			if (*(PWORD)buffptr_pattern == '\?\?' || *(PBYTE)buffptr_pattern != '\?') { buffptr_pattern += 3; }
			else { buffptr_pattern += 2; } //one ?
		}
		else
		{ // срыв совпадения
			buffptr_pattern = pattern;
			if (pMatch) { MemPtr = pMatch; }
			pMatch = 0;
		}
	}
	free(pattern);
	if (!pMatch || (*((char*)pMatch - 1) != '?')) { free(buff); return NULL; }
	//printf("found str: 0x%p\n", (char*)pMatch - 1); // print pointer 2 loaded file
	FARPROC pRes = GetProcAddress(hModule, (char*)pMatch - 1); // ? перед name
	free(buff);
	return pRes;
#undef getByte;
#undef getByte;
#undef INRANGE;
}