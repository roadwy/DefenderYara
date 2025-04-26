
rule TrojanDownloader_BAT_CobaltStrike_RKB_MTB{
	meta:
		description = "TrojanDownloader:BAT/CobaltStrike.RKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {34 37 2e 39 32 2e 31 33 31 2e 32 30 33 } //1 47.92.131.203
		$a_81_1 = {57 69 6e 64 6f 77 73 2e 70 64 62 } //1 Windows.pdb
		$a_81_2 = {53 65 6e 74 20 7b 30 7d 20 62 79 74 65 73 20 74 6f 20 73 65 72 76 65 72 } //1 Sent {0} bytes to server
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}