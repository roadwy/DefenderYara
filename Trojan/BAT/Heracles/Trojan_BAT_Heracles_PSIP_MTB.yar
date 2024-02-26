
rule Trojan_BAT_Heracles_PSIP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 0a 7e 64 00 00 04 0c 12 04 08 28 82 00 00 06 06 fe 06 42 01 00 06 73 66 00 00 0a 73 63 00 00 0a 0b 07 28 64 00 00 0a 06 28 68 00 00 0a 12 04 28 80 00 00 06 07 28 65 00 00 0a de 0e } //00 00 
	condition:
		any of ($a_*)
 
}