
rule Trojan_BAT_njRAT_NJ_MTB{
	meta:
		description = "Trojan:BAT/njRAT.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1a 13 09 } //5
		$a_81_1 = {67 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //2 get_UseSystemPasswordChar
		$a_81_2 = {34 63 34 39 32 62 34 35 2d 33 64 64 65 2d 34 32 38 66 2d 39 62 32 36 2d 65 33 36 36 62 33 38 66 61 30 63 66 } //2 4c492b45-3dde-428f-9b26-e366b38fa0cf
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=9
 
}