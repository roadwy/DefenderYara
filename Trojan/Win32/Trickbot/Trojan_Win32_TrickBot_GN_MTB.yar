
rule Trojan_Win32_TrickBot_GN_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 c0 90 01 01 89 45 fc 8b 4d fc 3b 4d 10 74 90 01 01 8b 45 fc 33 d2 f7 75 14 8b 45 0c 03 45 fc 8b 4d 08 8a 00 32 04 11 8b 4d 0c 03 4d fc 88 01 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_GN_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {6a 40 68 00 10 00 00 57 6a 00 ff d3 } //1
		$a_81_1 = {5c 44 4c 4c 50 4f 52 54 41 42 4c 45 58 38 36 5c 33 32 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 33 32 63 75 73 74 6f 6d 2e 70 64 62 } //1 \DLLPORTABLEX86\32\Release\dll32custom.pdb
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_3 = {55 6e 73 4f 72 65 74 57 } //1 UnsOretW
		$a_81_4 = {64 70 69 31 30 32 34 } //1 dpi1024
		$a_81_5 = {64 70 69 33 36 30 } //1 dpi360
		$a_81_6 = {64 70 69 36 34 30 } //1 dpi640
		$a_81_7 = {31 2e 64 6c 6c } //1 1.dll
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}