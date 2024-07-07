
rule TrojanDownloader_BAT_AgentTesla_BA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 3d 2b 42 2b 43 2b 48 16 16 2c 47 26 2b 17 2b 45 07 09 07 8e 69 5d 91 06 09 91 61 d2 6f } //2
		$a_01_1 = {32 00 33 00 2e 00 39 00 35 00 2e 00 31 00 30 00 36 00 2e 00 33 00 35 00 } //1 23.95.106.35
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}