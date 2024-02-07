
rule TrojanDownloader_O97M_Obfuse_RSER_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSER!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 73 63 68 72 68 63 75 4e } //01 00  Call schrhcuN
		$a_01_1 = {74 42 59 71 71 78 6d 46 5a 20 3d 20 52 65 70 6c 61 63 65 28 74 42 59 71 71 78 6d 46 5a 2c 20 22 72 71 77 67 61 72 7a 69 6d 73 77 22 2c 20 22 22 29 } //01 00  tBYqqxmFZ = Replace(tBYqqxmFZ, "rqwgarzimsw", "")
		$a_03_2 = {77 73 68 2e 52 75 6e 20 46 67 62 56 34 35 67 20 26 20 74 42 59 71 71 78 6d 46 5a 2c 20 2d 38 37 90 0c 02 00 25 51 51 51 25 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}