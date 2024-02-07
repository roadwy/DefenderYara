
rule TrojanDownloader_O97M_Obfuse_HA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 72 72 72 72 72 29 20 26 20 78 78 78 78 78 78 78 78 78 78 } //01 00  = Environ(rrrrr) & xxxxxxxxxx
		$a_00_1 = {53 68 65 6c 6c 6e 64 69 72 4f 62 6a 20 41 73 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //01 00  ShellndirObj As Shell32.Shell
		$a_00_2 = {42 79 70 61 73 73 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 46 69 6c 65 } //01 00  Bypass -windowstyle hidden -File
		$a_00_3 = {53 68 65 6c 6c 4f 62 6a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 65 65 } //01 00  ShellObj.ShellExecute ee
		$a_00_4 = {66 73 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 50 74 } //01 00  fs.CreateTextFile(Pt
		$a_00_5 = {67 31 20 3d 20 22 47 6e 6d 6d 62 6e 66 68 68 66 67 66 67 67 67 67 3d 3d 3d } //01 00  g1 = "Gnmmbnfhhfgfgggg===
		$a_00_6 = {53 74 72 69 6e 67 28 31 2c 20 78 36 29 20 2b 20 22 2e 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 78 37 29 } //00 00  String(1, x6) + "." + String(1, x7)
	condition:
		any of ($a_*)
 
}