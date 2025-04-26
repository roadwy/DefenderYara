
rule TrojanDownloader_BAT_AgentTesla_LSD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.LSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 63 32 37 61 32 61 65 33 2d 31 63 66 33 2d 34 37 33 62 2d 38 66 37 34 2d 37 64 38 34 66 64 65 63 65 64 31 37 } //1 $c27a2ae3-1cf3-473b-8f74-7d84fdeced17
		$a_01_1 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}