
rule Trojan_BAT_Malgent_MBAL_MTB{
	meta:
		description = "Trojan:BAT/Malgent.MBAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 11 04 8c ?? 00 00 01 a2 25 17 07 20 ef 04 00 00 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 07 20 ef 04 00 00 6f } //1
		$a_81_1 = {69 2e 69 62 62 2e 63 6f 2f 71 31 42 34 77 79 57 2f 6e 61 74 75 72 65 2d 66 69 65 6c 64 2d 67 72 61 2d 31 33 30 32 34 37 36 34 37 } //1 i.ibb.co/q1B4wyW/nature-field-gra-130247647
		$a_81_2 = {05 53 00 74 00 00 03 61 00 00 05 72 00 74 } //1
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}