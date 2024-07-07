
rule TrojanSpy_Win32_ThripKeyLogger{
	meta:
		description = "TrojanSpy:Win32/ThripKeyLogger,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 68 65 6c 70 5c 43 4e 44 59 2e 44 41 54 } //2 \help\CNDY.DAT
		$a_01_1 = {55 6e 6b 6e 6f 77 6e 20 56 69 72 74 75 61 6c 2d 4b 65 79 20 43 6f 64 65 } //1 Unknown Virtual-Key Code
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 28 29 20 66 61 69 6c 65 64 20 69 6e 20 4b 62 64 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 42 79 4e 61 6d 65 28 29 } //1 LoadLibraryA() failed in KbdGetProcAddressByName()
		$a_01_3 = {43 72 65 61 74 65 57 69 6e 64 6f 77 28 29 20 66 61 69 6c 65 64 20 69 6e 20 4b 62 64 52 65 67 69 73 74 65 72 43 72 65 61 74 65 48 69 64 65 57 69 6e 64 6f 77 28 29 } //1 CreateWindow() failed in KbdRegisterCreateHideWindow()
		$a_01_4 = {52 65 67 69 73 74 65 72 52 61 77 49 6e 70 75 74 44 65 76 69 63 65 73 } //1 RegisterRawInputDevices
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}