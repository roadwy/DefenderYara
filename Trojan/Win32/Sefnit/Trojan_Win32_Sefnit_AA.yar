
rule Trojan_Win32_Sefnit_AA{
	meta:
		description = "Trojan:Win32/Sefnit.AA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc 31 4d fc 83 90 03 04 04 3d 90 01 05 7d 90 01 02 90 17 03 02 01 01 0f 85 74 75 90 00 } //2
		$a_03_1 = {66 83 7e 08 3a 0f 85 90 01 04 90 02 08 66 83 7e 0a 2f 90 00 } //1
		$a_03_2 = {66 83 78 08 3a 0f 85 90 01 04 90 02 08 66 83 78 0a 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}