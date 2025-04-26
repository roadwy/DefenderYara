
rule TrojanDownloader_O97M_Obfuse_BXK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BXK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 38 69 6b 6f 74 22 2c 20 22 22 29 } //1 Replace(ActiveDocument.Content, "8ikot", "")
		$a_01_1 = {2e 72 75 6e 20 22 73 63 72 69 70 74 72 75 6e 6e 65 72 20 2d 61 70 70 76 73 63 72 69 70 74 20 22 20 26 20 69 6e 73 74 61 6c 6c 53 74 6f 70 4d 69 78 2c 20 32 } //1 .run "scriptrunner -appvscript " & installStopMix, 2
		$a_01_2 = {3d 20 22 2e 22 20 26 20 69 6e 73 74 61 6c 6c 53 74 6f 70 4d 69 78 20 26 20 73 74 61 72 74 50 61 75 73 65 50 6c 61 79 } //1 = "." & installStopMix & startPausePlay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}