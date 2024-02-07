
rule TrojanDownloader_BAT_AgentTesla_ABBR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_1 = {24 39 34 63 33 61 38 37 64 2d 38 34 35 62 2d 34 39 66 36 2d 61 61 34 66 2d 30 30 37 35 31 33 33 33 33 35 34 39 } //01 00  $94c3a87d-845b-49f6-aa4f-007513333549
		$a_01_2 = {62 00 61 00 73 00 6b 00 61 00 6e 00 70 00 72 00 6f 00 6a 00 65 00 73 00 69 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  baskanprojesi.Properties.Resources
		$a_01_3 = {6d 00 61 00 6e 00 69 00 74 00 61 00 2e 00 6e 00 65 00 72 00 64 00 65 00 73 00 69 00 6e 00 } //01 00  manita.nerdesin
		$a_01_4 = {63 00 6f 00 6d 00 62 00 6f 00 62 00 6f 00 78 00 } //01 00  combobox
		$a_01_5 = {79 00 61 00 72 00 6b 00 61 00 70 00 72 00 6f 00 6a 00 65 00 73 00 69 00 } //00 00  yarkaprojesi
	condition:
		any of ($a_*)
 
}