
rule Trojan_BAT_Heracles_MBFT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0a 1f 0a 13 05 2b b6 05 0e 04 61 1f 3b 59 06 61 } //01 00 
		$a_01_1 = {70 00 61 00 74 00 68 00 6f 00 6c 00 6f 00 67 00 69 00 73 00 74 00 2e 00 64 00 6c 00 6c 00 } //00 00  pathologist.dll
	condition:
		any of ($a_*)
 
}