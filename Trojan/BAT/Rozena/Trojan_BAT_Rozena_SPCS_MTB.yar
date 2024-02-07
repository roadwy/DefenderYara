
rule Trojan_BAT_Rozena_SPCS_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 08 08 8e 69 32 e7 09 8e 69 13 04 7e 90 01 03 0a 11 04 20 00 30 00 00 1f 40 28 90 01 03 06 13 05 09 16 11 05 90 00 } //01 00 
		$a_01_1 = {63 73 68 61 72 70 5f 72 75 6e 6e 65 72 2e 70 64 62 } //00 00  csharp_runner.pdb
	condition:
		any of ($a_*)
 
}