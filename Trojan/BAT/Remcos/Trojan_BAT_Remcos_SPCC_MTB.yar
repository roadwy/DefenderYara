
rule Trojan_BAT_Remcos_SPCC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 11 0f 17 58 13 0f } //00 00 
	condition:
		any of ($a_*)
 
}