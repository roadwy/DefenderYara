
rule Trojan_BAT_Remcos_APQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.APQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 da 0b 16 0c 2b 15 02 08 02 08 9a 03 72 90 01 01 01 00 70 6f 90 01 03 0a a2 08 17 d6 0c 08 07 31 e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}