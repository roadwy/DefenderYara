
rule TrojanDownloader_BAT_Small_SG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.SG!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 68 6f 73 74 77 72 69 74 69 6e 67 4e 61 72 64 } //01 00  GhostwritingNard
		$a_01_1 = {70 61 79 6c 6f 61 64 50 61 74 68 4f 72 55 52 4c } //01 00  payloadPathOrURL
		$a_01_2 = {67 65 74 45 54 57 50 61 79 6c 6f 61 64 } //01 00  getETWPayload
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 55 52 4c } //01 00  downloadURL
		$a_01_4 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //00 00  BeginInvoke
	condition:
		any of ($a_*)
 
}