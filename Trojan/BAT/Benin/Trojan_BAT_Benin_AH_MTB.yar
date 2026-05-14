
rule Trojan_BAT_Benin_AH_MTB{
	meta:
		description = "Trojan:BAT/Benin.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 7e 0a 01 00 04 7b 44 01 00 04 61 7e 76 01 00 04 28 e2 03 00 06 7e 11 00 00 04 7e 93 01 00 04 28 56 04 00 06 74 01 00 00 1b } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}