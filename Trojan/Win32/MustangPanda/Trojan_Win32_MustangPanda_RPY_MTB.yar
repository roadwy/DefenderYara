
rule Trojan_Win32_MustangPanda_RPY_MTB{
	meta:
		description = "Trojan:Win32/MustangPanda.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 00 32 00 33 00 2e 00 32 00 35 00 33 00 2e 00 33 00 32 00 2e 00 37 00 31 00 } //1 123.253.32.71
		$a_01_1 = {45 00 41 00 43 00 6f 00 72 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 EACore.dll
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 WindowsUpdate.exe
		$a_01_3 = {41 00 70 00 61 00 72 00 74 00 6d 00 65 00 6e 00 74 00 } //1 Apartment
		$a_01_4 = {0f b7 04 0a 66 3b c7 72 0d 66 3b c3 77 08 83 c0 20 0f b7 f0 eb 02 8b f0 0f b7 01 66 3b c7 72 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}