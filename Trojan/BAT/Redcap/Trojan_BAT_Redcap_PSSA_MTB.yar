
rule Trojan_BAT_Redcap_PSSA_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PSSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 97 02 00 70 28 11 00 00 0a 72 b3 02 00 70 28 12 00 00 0a 26 2b 0a 72 f1 02 00 70 28 11 00 00 0a 20 88 13 00 00 28 13 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}