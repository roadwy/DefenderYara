
rule TrojanDownloader_O97M_Obfuse_BBKO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BBKO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4e 41 4d 45 4d 45 2e 6b 71 57 5a 5a 28 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 4b 4e 4f 5a 28 29 2c 20 58 55 4e 4b 76 28 29 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 30 29 } //1 = NAMEME.kqWZZ().ShellExecute(KNOZ(), XUNKv(), Null, Null, 0)
		$a_01_1 = {57 53 4e 68 35 20 3d 20 2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } //1 WSNh5 = .Shapes(1).TextFrame.Characters.Text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}