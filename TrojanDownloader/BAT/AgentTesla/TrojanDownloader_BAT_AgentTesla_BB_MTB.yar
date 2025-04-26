
rule TrojanDownloader_BAT_AgentTesla_BB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 09 8e 69 13 04 2b 0a 06 09 11 04 91 6f ?? ?? ?? 0a 11 04 25 17 59 13 04 16 fe 02 2d ea } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}