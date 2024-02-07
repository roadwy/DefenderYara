
rule TrojanDownloader_O97M_Obfuse_IBK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IBK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 27 2c 27 68 74 74 70 73 3a 2f 2f 61 2e 70 6f 6d 66 2e 63 61 74 2f 75 71 75 79 71 73 2e 74 } //01 00  Open','https://a.pomf.cat/uquyqs.t
		$a_01_1 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 6a 72 68 75 55 4a 68 67 31 20 26 20 22 5c 22 20 26 20 22 72 62 65 72 62 72 2e 6a 73 22 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //01 00  .CreateTextFile(jrhuUJhg1 & "\" & "rberbr.js", True, True)
		$a_01_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 73 74 61 72 74 20 22 20 26 20 6a 72 68 75 55 4a 68 67 31 20 26 20 22 5c 22 20 26 20 22 72 62 65 72 62 72 2e 6a 73 22 2c 20 76 62 48 69 64 65 } //00 00  Shell Environ("COMSPEC") & " /c start " & jrhuUJhg1 & "\" & "rberbr.js", vbHide
	condition:
		any of ($a_*)
 
}