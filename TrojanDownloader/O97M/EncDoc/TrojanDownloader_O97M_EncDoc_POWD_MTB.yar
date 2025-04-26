
rule TrojanDownloader_O97M_EncDoc_POWD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.POWD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 20 28 46 46 29 } //1 exec (FF)
		$a_01_1 = {53 75 62 20 65 78 65 63 28 41 74 63 29 } //1 Sub exec(Atc)
		$a_03_2 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f [0-30] 2f [0-20] 2e 68 74 6d 6c 22 } //1
		$a_01_3 = {53 65 74 20 6f 62 6a 53 74 61 72 74 75 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 Set objStartup = objWMIService.Get("Win32_ProcessStartup")
		$a_01_4 = {53 65 74 20 6f 62 6a 43 6f 6e 66 69 67 20 3d 20 6f 62 6a 53 74 61 72 74 75 70 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //1 Set objConfig = objStartup.SpawnInstance_
		$a_01_5 = {6f 62 6a 43 6f 6e 66 69 67 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 30 } //1 objConfig.ShowWindow = 0
		$a_01_6 = {53 65 74 20 6f 62 6a 50 72 6f 63 65 73 73 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 Set objProcess = objWMIService.Get("Win32_Process")
		$a_01_7 = {69 6e 74 52 65 74 75 72 6e 20 3d 20 6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 28 73 74 72 43 6f 6d 6d 61 6e 64 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1 intReturn = objProcess.Create(strCommand, Null, objConfig, intProcessID)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}