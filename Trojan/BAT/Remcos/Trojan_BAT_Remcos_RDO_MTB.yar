
rule Trojan_BAT_Remcos_RDO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 06 6f 17 00 00 0a 16 73 18 00 00 0a 0d } //00 00 
	condition:
		any of ($a_*)
 
}