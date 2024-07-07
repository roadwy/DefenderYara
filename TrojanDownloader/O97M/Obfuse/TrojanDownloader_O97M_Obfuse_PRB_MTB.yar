
rule TrojanDownloader_O97M_Obfuse_PRB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 52 65 70 6c 61 63 65 28 79 51 65 6d 52 49 46 2c 20 22 76 72 69 72 79 76 66 22 2c 20 22 22 29 } //1 = Replace(yQemRIF, "vriryvf", "")
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 55 43 46 63 71 63 57 6d 62 2c 20 22 62 76 77 63 70 6d 6a 68 74 22 2c 20 22 22 29 } //1 = Replace(UCFcqcWmb, "bvwcpmjht", "")
		$a_00_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
		$a_00_3 = {6f 62 6a 53 74 61 72 74 55 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 objStartUp = objWMIService.Get("Win32_ProcessStartup")
		$a_00_4 = {3d 20 6f 62 6a 53 74 61 72 74 55 70 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //1 = objStartUp.SpawnInstance_
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}