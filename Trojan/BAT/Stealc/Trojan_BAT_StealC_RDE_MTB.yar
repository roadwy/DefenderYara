
rule Trojan_BAT_StealC_RDE_MTB{
	meta:
		description = "Trojan:BAT/StealC.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 59 09 59 20 00 01 00 00 5d 13 04 11 04 16 } //00 00 
	condition:
		any of ($a_*)
 
}