
rule TrojanDownloader_O97M_Netwire_PDB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 31 28 58 78 58 2c 20 61 41 61 29 20 2b 20 55 52 4c 28 58 78 58 2c 20 61 41 61 29 20 2b 20 63 6d 64 32 28 58 78 58 2c 20 61 41 61 29 } //1 cmd1(XxX, aAa) + URL(XxX, aAa) + cmd2(XxX, aAa)
		$a_03_1 = {53 68 65 6c 6c 20 90 02 0a 2c 20 76 62 48 69 64 65 90 00 } //1
		$a_01_2 = {55 52 4c 20 3d 20 22 22 22 65 78 65 2e 6c 6c 64 2f 6c 6d 74 68 2f 6d 6f 63 2e 6d 69 78 65 70 6c 75 74 2f 2f 3a 70 74 74 68 22 } //1 URL = """exe.lld/lmth/moc.mixeplut//:ptth"
		$a_01_3 = {55 52 4c 20 3d 20 22 22 22 65 78 65 2e 64 65 72 72 61 6a 2f 6d 74 79 61 70 2f 6d 6f 63 2e 65 6e 79 64 6c 65 6c 65 74 2f 2f 3a 73 70 74 74 68 22 } //1 URL = """exe.derraj/mtyap/moc.enydlelet//:sptth"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}