
rule Trojan_BAT_XWorm_ARR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 74 ?? ?? ?? ?? 16 14 1d 20 } //15
		$a_01_1 = {13 0b 13 11 11 11 14 14 16 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}
rule Trojan_BAT_XWorm_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b 14 14 17 8d ?? ?? ?? ?? 13 11 11 11 74 ?? ?? ?? ?? 16 17 9c 11 11 } //9
		$a_03_1 = {13 0f 11 0f 74 ?? ?? ?? ?? 16 11 0c 74 ?? ?? ?? ?? a2 11 0f 74 ?? ?? ?? ?? 13 10 11 10 } //11
	condition:
		((#a_03_0  & 1)*9+(#a_03_1  & 1)*11) >=20
 
}