
rule Trojan_Win32_Ursnif_SG_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 03 45 f8 8b 4d f4 03 4d f8 8a 11 88 10 8b 45 f8 83 c0 01 89 45 f8 eb } //1
		$a_01_1 = {03 45 fc 8b 55 08 03 02 8b 4d 08 89 01 8b e5 5d c3 } //1
		$a_03_2 = {ba b2 19 00 00 31 0d 90 01 03 00 a1 90 01 03 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}