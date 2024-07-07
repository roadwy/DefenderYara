
rule TrojanDownloader_O97M_EncDoc_PAT_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6d 6f 64 75 6c 65 31 22 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 64 65 } //1 vb_name="module1"subauto_open()de
		$a_01_1 = {76 62 61 2e 73 68 65 6c 6c 28 6f 63 78 7a 77 31 61 63 70 2b 6c 75 6c 64 39 71 78 66 6f 2b 74 66 73 31 77 7a 68 72 64 29 29 65 6e 64 73 } //1 vba.shell(ocxzw1acp+luld9qxfo+tfs1wzhrd))ends
		$a_01_2 = {3d 34 74 6f 31 31 64 6f 65 76 65 6e 74 73 6e 65 78 74 6a 6c 73 6b 77 61 61 61 6c 66 79 75 64 69 6d 6d 72 61 62 7a 65 62 69 70 75 67 67 76 61 61 73 73 74 72 69 6e 67 6d 72 61 62 7a 65 62 69 70 75 67 67 76 61 3d 22 34 30 32 38 22 65 } //1 =4to11doeventsnextjlskwaaalfyudimmrabzebipuggvaasstringmrabzebipuggva="4028"e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}