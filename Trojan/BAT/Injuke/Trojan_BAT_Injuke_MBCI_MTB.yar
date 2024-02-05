
rule Trojan_BAT_Injuke_MBCI_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 1f 10 2b 15 2b 1a 2b 1f 2b 20 2b 25 2b 26 2a 28 90 01 01 00 00 0a 2b d5 0a 2b d4 90 00 } //01 00 
		$a_01_1 = {53 00 65 00 76 00 67 00 75 00 63 00 61 00 6b 00 75 00 7a 00 62 00 6e 00 72 00 7a 00 6a 00 78 00 67 00 6a 00 6c 00 2e 00 5a 00 67 00 6a 00 61 00 67 00 62 00 71 00 70 00 69 00 70 00 61 00 63 00 64 } //01 00 
		$a_01_2 = {45 00 62 00 76 00 6f 00 71 00 68 00 75 00 73 00 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}