
rule Trojan_BAT_Heracles_KAM_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {18 5a 94 02 11 05 18 5a 17 58 94 58 9e 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}