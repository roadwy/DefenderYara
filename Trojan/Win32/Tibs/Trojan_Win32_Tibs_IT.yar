
rule Trojan_Win32_Tibs_IT{
	meta:
		description = "Trojan:Win32/Tibs.IT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 83 c9 ff 66 41 66 8b 11 66 81 f2 90 01 02 66 81 fa 90 01 02 74 90 01 01 81 e9 90 01 04 81 e9 90 00 } //1
		$a_03_1 = {8b 55 08 01 c2 8b 4d fc 89 d6 c9 c2 04 00 90 09 02 00 cd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}