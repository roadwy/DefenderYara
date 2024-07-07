
rule Trojan_BAT_Redlinestealer_SK_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 04 06 08 06 09 91 9c 06 09 11 04 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff } //2
		$a_81_1 = {24 64 31 37 62 34 31 63 39 2d 33 39 35 35 2d 34 38 39 30 2d 39 35 62 38 2d 38 38 37 61 61 63 30 30 36 65 30 62 } //2 $d17b41c9-3955-4890-95b8-887aac006e0b
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}