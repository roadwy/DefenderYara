
rule Trojan_BAT_Redcap_PTCS_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PTCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 40 d6 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 02 6f 34 00 00 06 0c 08 08 6f 72 00 00 0a 06 28 90 01 01 00 00 0a 07 72 e3 00 00 70 28 90 01 01 00 00 0a 6f 75 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}