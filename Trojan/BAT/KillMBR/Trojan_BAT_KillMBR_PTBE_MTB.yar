
rule Trojan_BAT_KillMBR_PTBE_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.PTBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 52 01 00 70 20 00 02 00 00 13 0a 12 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 00 72 6c 01 00 70 08 28 90 01 01 00 00 0a 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}