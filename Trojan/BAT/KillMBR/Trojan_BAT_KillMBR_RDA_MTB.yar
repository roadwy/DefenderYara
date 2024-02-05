
rule Trojan_BAT_KillMBR_RDA_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {19 16 7e 1e 00 00 0a 28 90 01 04 0b 07 06 20 00 80 00 00 12 02 7e 1e 00 00 0a 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}