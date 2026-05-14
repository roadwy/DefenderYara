
rule Trojan_BAT_DarkCloud_SM_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 12 11 14 11 12 11 14 d6 28 9d 01 00 0a 11 09 11 12 11 14 11 12 11 14 d8 28 9d 01 00 0a 11 14 17 d6 13 14 11 14 11 13 31 d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}