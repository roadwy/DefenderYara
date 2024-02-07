
rule Trojan_BAT_NjRat_NEBL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {13 04 11 04 13 05 06 1a 58 16 54 06 1e 58 11 05 06 1a 58 28 52 00 00 06 54 7e d7 00 00 04 06 1e 58 4a 28 55 00 00 06 28 d9 00 00 06 13 06 } //02 00 
		$a_01_1 = {53 74 75 62 2e 65 78 65 } //02 00  Stub.exe
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 30 2e 32 2e 34 37 37 39 } //00 00  Powered by SmartAssembly 8.0.2.4779
	condition:
		any of ($a_*)
 
}