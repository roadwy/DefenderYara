
rule Trojan_Win32_Lamer_C_MTB{
	meta:
		description = "Trojan:Win32/Lamer.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 2c 22 53 55 43 43 45 53 53 22 2c 22 30 78 30 30 39 39 30 30 30 30 22 2c 22 74 68 33 32 50 72 6f 63 65 73 73 49 44 2d 3e 31 38 32 34 22 2c 22 73 7a 45 78 65 46 69 6c 65 2d 3e 48 65 6c 70 4d 65 2e 65 78 65 22 2c 22 6c 70 41 64 64 72 65 73 73 2d 3e 30 78 30 30 30 30 30 30 30 30 22 2c 22 64 77 53 69 7a 65 2d 3e 34 30 39 36 22 2c 22 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 2d 3e 30 78 30 30 30 30 31 30 30 30 22 2c 22 66 6c 50 72 6f 74 65 63 74 2d 3e 30 78 30 30 30 30 30 30 34 30 } //2 VirtualAllocEx","SUCCESS","0x00990000","th32ProcessID->1824","szExeFile->HelpMe.exe","lpAddress->0x00000000","dwSize->4096","flAllocationType->0x00001000","flProtect->0x00000040
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 41 75 74 6f 52 75 6e 2e 65 78 65 } //1 shellexecute=AutoRun.exe
		$a_01_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //1 Internet Explorer.lnk
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}