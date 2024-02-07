
rule TrojanDownloader_O97M_Powdow_YD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 65 66 69 6e 65 64 5f 46 72 65 73 68 5f 50 61 6e 74 73 61 77 76 20 3d 20 52 6f 61 64 73 62 6e 7a 20 2b 20 28 22 90 02 04 22 29 20 2b 20 52 6f 61 64 73 62 6e 7a 20 2b 20 28 22 90 02 06 22 29 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 67 6c 6f 62 61 6c 77 69 6a 20 2b 20 55 53 42 7a 69 6f 28 47 72 61 6e 69 74 65 6b 75 77 2e 47 6c 6f 62 61 6c 68 71 68 } //01 00  CreateObject(globalwij + USBzio(Granitekuw.Globalhqh
		$a_01_2 = {63 6f 6c 6c 61 62 6f 72 61 74 69 76 65 74 7a 6a 2e 53 68 6f 77 57 69 6e 64 6f 77 21 20 3d 20 49 6e 74 28 30 29 } //00 00  collaborativetzj.ShowWindow! = Int(0)
	condition:
		any of ($a_*)
 
}