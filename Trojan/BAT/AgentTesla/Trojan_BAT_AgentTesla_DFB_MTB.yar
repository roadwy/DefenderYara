
rule Trojan_BAT_AgentTesla_DFB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 08 11 02 02 11 02 91 11 90 01 01 61 d2 9c 90 00 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 74 00 6f 00 72 00 65 00 32 00 2e 00 67 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 69 00 6f 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 } //01 00  https://store2.gofile.io/download/
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //0a 00  https://cdn.discordapp.com/attachments/
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //0a 00  GetExportedTypes
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}