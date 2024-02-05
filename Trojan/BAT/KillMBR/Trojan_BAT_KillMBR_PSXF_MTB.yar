
rule Trojan_BAT_KillMBR_PSXF_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.PSXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 11 00 00 01 0a 72 01 00 00 70 20 00 00 00 10 19 7e 0f 00 00 0a 19 16 7e 0f 00 00 0a 28 90 01 01 00 00 06 0b 07 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}