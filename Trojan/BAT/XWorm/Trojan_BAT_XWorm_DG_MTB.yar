
rule Trojan_BAT_XWorm_DG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 } //3
		$a_01_1 = {00 11 04 11 0c 11 0c 9e 00 11 0c 17 58 13 0c } //1
		$a_01_2 = {45 00 34 00 5a 00 44 00 46 00 41 00 34 00 55 00 38 00 58 00 35 00 35 00 37 00 39 00 47 00 34 00 56 00 46 00 53 00 39 00 35 00 47 00 } //1 E4ZDFA4U8X5579G4VFS95G
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}