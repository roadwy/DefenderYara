
rule Trojan_BAT_Remcos_RDL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 86 00 00 0a 0d 09 28 01 00 00 2b 28 02 00 00 2b 0d } //00 00 
	condition:
		any of ($a_*)
 
}