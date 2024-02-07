
rule TrojanDownloader_BAT_Small_ARAU_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.ARAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 37 32 33 38 39 20 62 69 6e 64 65 72 20 73 74 75 62 5c 6f 62 6a 5c 44 65 62 75 67 5c 37 32 33 38 39 20 62 69 6e 64 65 72 20 73 74 75 62 2e 70 64 62 } //02 00  \72389 binder stub\obj\Debug\72389 binder stub.pdb
		$a_03_1 = {04 20 ff 00 00 00 5f 2b 1d 03 6f 90 01 03 0a 0c 2b 17 08 06 08 06 93 02 7b 90 01 03 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}