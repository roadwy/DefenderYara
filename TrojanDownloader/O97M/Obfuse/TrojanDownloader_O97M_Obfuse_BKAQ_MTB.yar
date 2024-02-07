
rule TrojanDownloader_O97M_Obfuse_BKAQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BKAQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 66 70 20 3d 20 6e 64 70 20 26 20 22 75 70 64 61 74 65 2e 65 78 65 22 } //01 00  ofp = ndp & "update.exe"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6b 6b 20 26 20 6c 6c 20 26 20 22 64 22 20 26 20 6d 6d 20 26 20 22 76 69 63 65 22 29 } //01 00  = CreateObject(kk & ll & "d" & mm & "vice")
		$a_01_2 = {43 61 6c 6c 20 6f 6f 2e 52 65 67 69 73 74 65 72 54 61 73 6b 28 22 4d 69 63 72 6f 73 6f 66 74 55 70 64 61 74 65 22 2c 20 78 74 2c 20 36 2c 20 2c 20 2c 20 33 29 } //00 00  Call oo.RegisterTask("MicrosoftUpdate", xt, 6, , , 3)
	condition:
		any of ($a_*)
 
}