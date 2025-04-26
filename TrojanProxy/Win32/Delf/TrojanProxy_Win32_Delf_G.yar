
rule TrojanProxy_Win32_Delf_G{
	meta:
		description = "TrojanProxy:Win32/Delf.G,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 6c 79 61 62 75 64 75 2e 69 6e 66 6f 2f 70 6e 67 2e 65 78 65 } //1 http://blyabudu.info/png.exe
		$a_01_1 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //1 Portions Copyright (c) 1999,2003 Avenger by NhT
		$a_01_2 = {64 6e 73 61 70 69 2e 64 6c 6c } //1 dnsapi.dll
		$a_01_3 = {26 75 73 65 6e 61 6d 65 73 3d 31 26 73 6d 61 72 74 70 69 63 3d 31 26 72 61 6e 64 3d } //1 &usenames=1&smartpic=1&rand=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}