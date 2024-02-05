
rule TrojanDownloader_BAT_Barys_CXJK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Barys.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6f 00 6e 00 65 00 64 00 72 00 69 00 76 00 65 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 3f 00 63 00 69 00 64 00 3d 00 38 00 39 00 37 00 39 00 39 00 31 00 31 00 42 00 38 00 30 00 41 00 38 00 44 00 43 00 44 00 31 } //00 00 
	condition:
		any of ($a_*)
 
}