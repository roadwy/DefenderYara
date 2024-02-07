
rule TrojanDropper_O97M_Obfuse_BH_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 20 26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 2c 20 79 79 20 26 20 22 5c 57 22 20 26 20 22 30 72 64 2e 64 22 20 26 20 22 6c 6c 2c 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  .ShellExecute(fa & jsd & "ll" & hh, yy & "\W" & "0rd.d" & "ll,DllUnregisterServer
		$a_00_1 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c } //01 00  ActiveDocument.AttachedTemplate.Path & "\W0rd.dll
		$a_00_2 = {4c 6f 63 22 20 26 20 22 61 6c 5c 54 65 22 20 26 20 22 6d 70 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 } //01 00  Loc" & "al\Te" & "mp", vbDirectory
		$a_00_3 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 } //00 00  = ActiveDocument.AttachedTemplate.Path & "\W0rd.dll"
	condition:
		any of ($a_*)
 
}