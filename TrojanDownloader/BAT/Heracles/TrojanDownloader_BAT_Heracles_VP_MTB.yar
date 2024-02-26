
rule TrojanDownloader_BAT_Heracles_VP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_81_0 = {54 72 61 64 65 6d 61 72 6b 20 2d 20 4c 69 6d 65 } //02 00  Trademark - Lime
		$a_81_1 = {24 4c 69 6d 65 55 53 42 5c 4c 69 6d 65 55 53 42 2e 65 78 65 } //00 00  $LimeUSB\LimeUSB.exe
	condition:
		any of ($a_*)
 
}