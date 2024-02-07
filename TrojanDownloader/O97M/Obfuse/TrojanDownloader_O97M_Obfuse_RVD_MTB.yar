
rule TrojanDownloader_O97M_Obfuse_RVD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 53 68 65 6c 6c 2e 72 75 6e 20 22 22 77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 42 20 22 22 20 26 20 43 68 72 28 33 34 29 20 26 20 64 69 72 20 26 20 22 22 72 6b 6e 72 6c 2e 76 62 73 22 22 20 26 20 43 68 72 28 33 34 29 3a 77 73 70 72 20 3d 20 57 53 68 65 6c 6c 2e 72 65 67 72 65 61 64 } //01 00  WShell.run ""wscript.exe //B "" & Chr(34) & dir & ""rknrl.vbs"" & Chr(34):wspr = WShell.regread
		$a_00_1 = {56 42 53 70 61 74 68 20 3d 20 67 50 61 74 68 20 26 20 22 5c 72 6b 6e 72 6c 2e 76 62 73 22 } //01 00  VBSpath = gPath & "\rknrl.vbs"
		$a_00_2 = {44 4d 70 61 74 68 20 3d 20 67 50 61 74 68 20 26 20 22 5c 44 4d 36 33 33 31 2e 54 4d 50 22 } //01 00  DMpath = gPath & "\DM6331.TMP"
		$a_00_3 = {57 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 22 29 } //01 00  WShell = CreateObject(""WScript.Shell"")
		$a_00_4 = {52 65 70 6c 61 63 65 28 44 4d 2c 20 22 22 22 22 2c 20 22 22 22 22 22 22 29 } //01 00  Replace(DM, """", """""")
		$a_00_5 = {57 73 63 7c 72 69 70 7c 74 2e 53 7c 63 72 69 7c 70 74 46 7c 75 6c 6c 7c 4e 61 6d 7c 65 29 2e 7c 50 61 72 7c 65 6e 74 7c 46 6f 6c 7c 64 65 72 7c 2e 50 61 7c 74 68 26 7c 22 22 5c 7c 44 4d 36 7c 33 33 31 7c 2e 54 4d 7c 50 22 } //00 00  Wsc|rip|t.S|cri|ptF|ull|Nam|e).|Par|ent|Fol|der|.Pa|th&|""\|DM6|331|.TM|P"
	condition:
		any of ($a_*)
 
}