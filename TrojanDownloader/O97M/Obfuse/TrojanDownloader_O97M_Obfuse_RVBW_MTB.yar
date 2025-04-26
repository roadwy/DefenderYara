
rule TrojanDownloader_O97M_Obfuse_RVBW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 65 73 71 62 66 61 66 67 61 69 61 61 67 61 63 67 61 74 67 62 6c 61 68 63 61 6c 71 62 70 61 67 69 61 61 67 62 6c 61 67 6d 61 64 61 61 67 61 65 34 61 7a 71 62 30 61 63 34 61 76 77 62 6c 61 67 69 61 71 77 62 73 61 67 6b 61 7a 71 62 75 61 68 71 61 6b 71 61 75 61 65 71 61 62 77 62 33 61 67 34 61 62 61 62 76 61 67 65 61 7a 61 62 74 61 68 71 61 63 67 62 70 61 67 34 61 7a 77 61 75 61 65 6b 61 62 67 62 32 61 67 38 61 61 77 62 6c 61 63 67 61 6a 77 61 6e 61 61 6f 61 61 61 62 30 61 68 71 61 63 61 62 7a 61 64 6f 61 6c 77 61 76 61 } //1 -esqbfafgaiaagacgatgblahcalqbpagiaagblagmadaagae4azqb0ac4avwblagiaqwbsagkazqbuahqakqauaeqabwb3ag4ababvageazabtahqacgbpag4azwauaekabgb2ag8aawblacgajwanaaoaaab0ahqacabzadoalwava
		$a_01_1 = {3d 22 77 22 3a 65 72 3d 22 73 22 3a 74 79 3d 22 63 22 3a 75 69 3d 22 72 22 3a 64 66 3d 22 69 22 3a 67 68 3d 22 70 22 } //1 ="w":er="s":ty="c":ui="r":df="i":gh="p"
		$a_01_2 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 78 71 6d 63 72 6b 29 61 6c 78 7a 2e 72 75 6e } //1 =createobject(xqmcrk)alxz.run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}