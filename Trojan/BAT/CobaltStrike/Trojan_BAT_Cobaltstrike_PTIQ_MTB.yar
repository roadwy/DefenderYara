
rule Trojan_BAT_Cobaltstrike_PTIQ_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PTIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0a 03 16 06 03 8e 69 28 90 01 01 00 00 0a 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}