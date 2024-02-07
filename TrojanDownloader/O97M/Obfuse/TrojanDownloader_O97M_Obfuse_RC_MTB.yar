
rule TrojanDownloader_O97M_Obfuse_RC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 66 20 49 73 44 61 74 65 28 90 02 0a 29 20 41 6e 64 20 28 28 90 00 } //01 00 
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0a 2c 20 22 90 02 14 22 2c 20 22 22 29 90 00 } //01 00 
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 22 20 26 20 22 6c 22 29 } //01 00  = CreateObject("WScript.Shel" & "l")
		$a_01_3 = {65 6e 62 6d 67 67 72 2e 52 75 6e } //00 00  enbmggr.Run
	condition:
		any of ($a_*)
 
}