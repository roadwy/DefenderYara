
rule Trojan_Win32_GuLoader_M_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 45 00 58 00 45 00 22 00 20 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //3 Windows\explorer.EXE" C:\windows\system32\svchost.exe
		$a_81_1 = {55 6e 69 6e 73 74 61 6c 6c 5c 50 44 46 5f 52 65 61 64 65 72 } //3 Uninstall\PDF_Reader
		$a_81_2 = {49 6e 69 74 69 61 74 65 53 68 75 74 64 6f 77 6e 57 } //3 InitiateShutdownW
		$a_81_3 = {53 69 6d 70 6c 65 2e 70 6e 67 } //3 Simple.png
		$a_81_4 = {53 69 6d 70 6c 65 43 6f 6c 6f 72 2e 64 6c 6c } //3 SimpleColor.dll
		$a_81_5 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 57 28 69 20 72 32 2c 20 69 20 30 2c 20 69 20 30 78 34 30 2c 20 69 20 30 2c 20 69 20 30 2c 20 69 20 30 29 69 2e 72 33 } //3 CreateFileMappingW(i r2, i 0, i 0x40, i 0, i 0, i 0)i.r3
		$a_81_6 = {43 6c 61 73 73 69 63 2e 70 6e 67 } //3 Classic.png
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}