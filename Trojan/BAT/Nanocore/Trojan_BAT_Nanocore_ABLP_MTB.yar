
rule Trojan_BAT_Nanocore_ABLP_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f 90 01 03 0a 0a 2b 00 06 2a 90 0a 19 00 7e 90 01 03 04 6f 90 00 } //01 00 
		$a_01_1 = {68 00 6b 00 79 00 78 00 44 00 70 00 45 00 68 00 70 00 51 00 78 00 4f 00 69 00 45 00 73 00 68 00 51 00 43 00 72 00 44 00 70 00 } //01 00  hkyxDpEhpQxOiEshQCrDp
		$a_01_2 = {50 00 43 00 4d 00 42 00 69 00 6e 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  PCMBinBuilder.Properties.Resources
	condition:
		any of ($a_*)
 
}