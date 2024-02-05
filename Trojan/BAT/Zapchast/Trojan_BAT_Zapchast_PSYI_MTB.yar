
rule Trojan_BAT_Zapchast_PSYI_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PSYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 36 00 00 0a 25 28 90 01 01 00 00 0a 6f 38 00 00 0a 72 92 01 00 70 28 90 01 01 00 00 0a 6f 3a 00 00 0a 0a 06 72 ea 01 00 70 72 f0 01 00 70 6f 3b 00 00 0a 0a 72 f4 01 00 70 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}