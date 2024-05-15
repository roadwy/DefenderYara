
rule Trojan_BAT_Remcos_AMMD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {17 58 09 5d 91 13 90 02 1e 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}