
rule Trojan_BAT_Razy_PTEC_MTB{
	meta:
		description = "Trojan:BAT/Razy.PTEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 28 54 00 00 06 0c 11 07 20 e5 e9 b2 53 5a 20 3a 73 10 52 } //00 00 
	condition:
		any of ($a_*)
 
}