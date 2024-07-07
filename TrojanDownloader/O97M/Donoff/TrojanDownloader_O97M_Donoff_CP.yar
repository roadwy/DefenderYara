
rule TrojanDownloader_O97M_Donoff_CP{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CP,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 20 3d 20 53 74 72 20 2b 20 22 64 64 65 6e 20 2d 45 6e 63 20 57 77 22 } //4 Str = Str + "dden -Enc Ww"
		$a_01_1 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 20 53 74 72 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 } //2 objProcess.Create Str, Null, objConfig, 
		$a_01_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 65 62 75 67 67 69 6e 67 28 29 20 41 73 20 56 61 72 69 61 6e 74 } //2 Public Function Debugging() As Variant
		$a_01_3 = {53 74 72 20 3d 20 53 74 72 20 2b 20 22 50 20 2d 73 74 61 20 2d 4e 22 } //4 Str = Str + "P -sta -N"
		$a_01_4 = {73 74 72 43 6f 6d 70 75 74 65 72 20 3d 20 22 2e 22 } //3 strComputer = "."
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3) >=15
 
}
rule TrojanDownloader_O97M_Donoff_CP_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CP,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 73 74 61 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 45 6e 63 20 57 77 42 54 22 } //1 Str = "powershell.exe -NoP -sta -NonI -W Hidden -Enc WwBT"
		$a_01_1 = {6f 62 6a 43 6f 6e 66 69 67 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 48 49 44 44 45 4e 5f 57 49 4e 44 4f 57 } //1 objConfig.ShowWindow = HIDDEN_WINDOW
		$a_01_2 = {73 74 72 43 6f 6d 70 75 74 65 72 20 3d 20 22 2e 22 } //1 strComputer = "."
		$a_01_3 = {53 65 74 20 6f 62 6a 53 74 61 72 74 75 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 Set objStartup = objWMIService.Get("Win32_ProcessStartup")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}