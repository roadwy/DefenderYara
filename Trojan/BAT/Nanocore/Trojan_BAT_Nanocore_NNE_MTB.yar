
rule Trojan_BAT_Nanocore_NNE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 0a 06 28 90 01 01 00 00 0a 25 26 0b 28 90 01 01 00 00 0a 25 26 07 16 07 8e 69 6f 90 01 01 00 00 0a 25 26 0a 28 90 01 01 00 00 0a 25 26 06 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {4e 4e 6e 48 37 36 } //00 00 
	condition:
		any of ($a_*)
 
}