
rule TrojanDownloader_O97M_AgentTesla_RS_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 64 61 73 33 20 3d 20 22 74 22 20 2b 20 22 61 20 68 74 22 } //01 00  pdas3 = "t" + "a ht"
		$a_00_1 = {53 68 65 6c 6c 20 70 6b 6b 6b 6b } //01 00  Shell pkkkk
		$a_02_2 = {6f 6b 66 66 72 20 3d 20 22 61 6b 90 02 0f 64 64 77 69 64 22 90 00 } //01 00 
		$a_00_3 = {6b 61 73 6b 64 6b 2e 68 69 73 73 73 73 61 } //01 00  kaskdk.hissssa
		$a_00_4 = {6b 6f 34 64 20 3d 20 22 74 70 3a 2f 2f 25 37 34 38 32 33 37 25 37 32 38 37 34 38 40 6a 2e 6d 70 2f 22 } //00 00  ko4d = "tp://%748237%728748@j.mp/"
	condition:
		any of ($a_*)
 
}