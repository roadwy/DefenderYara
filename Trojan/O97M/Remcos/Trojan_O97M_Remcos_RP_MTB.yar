
rule Trojan_O97M_Remcos_RP_MTB{
	meta:
		description = "Trojan:O97M/Remcos.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 32 30 39 2e 31 32 37 2e 32 30 2e 31 33 2f } //00 00 
	condition:
		any of ($a_*)
 
}