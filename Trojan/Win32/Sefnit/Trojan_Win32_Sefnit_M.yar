
rule Trojan_Win32_Sefnit_M{
	meta:
		description = "Trojan:Win32/Sefnit.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 8c 28 f4 fe ff ff } //1
		$a_01_1 = {88 94 29 f4 fe ff ff } //1
		$a_01_2 = {8b e5 5d ff 25 } //1
		$a_02_3 = {8b 14 8e 81 f2 90 01 04 89 14 8f 83 f9 00 75 02 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}