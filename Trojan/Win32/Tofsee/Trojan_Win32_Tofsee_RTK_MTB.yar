
rule Trojan_Win32_Tofsee_RTK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 03 8d 90 01 04 03 d7 33 c2 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 90 00 } //1
		$a_02_1 = {c1 e9 05 03 4c 24 90 01 01 03 d6 33 c2 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 89 2d 90 01 04 89 2d 90 01 04 89 44 24 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}