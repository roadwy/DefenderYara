
rule Trojan_BAT_Remcos_SPCP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 11 0d 06 11 0d 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 0d 17 58 13 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}