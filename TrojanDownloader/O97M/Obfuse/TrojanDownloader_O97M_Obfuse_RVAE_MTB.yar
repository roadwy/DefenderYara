
rule TrojanDownloader_O97M_Obfuse_RVAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.Shell")
		$a_03_1 = {49 6e 53 74 72 28 90 02 64 2c 20 4d 69 64 28 90 02 64 2c 20 69 2c 20 31 29 29 90 00 } //01 00 
		$a_01_2 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 22 50 6c 65 61 73 65 20 77 61 69 74 22 } //01 00  Range("A1").Value = "Please wait"
		$a_03_3 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 90 02 64 28 22 90 02 64 22 29 2c 20 46 61 6c 73 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}