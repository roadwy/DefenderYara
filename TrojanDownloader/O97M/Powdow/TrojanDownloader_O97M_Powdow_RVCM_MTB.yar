
rule TrojanDownloader_O97M_Powdow_RVCM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 74 70 3a 2f 2f 35 32 35 37 35 38 31 35 2d 33 38 2d 32 30 32 30 30 34 30 36 31 32 30 36 33 34 2e 77 65 62 73 74 61 72 74 65 72 7a 2e 63 6f 6d 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? 22 } //1
		$a_03_1 = {64 73 74 72 66 69 6c 65 3d 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? 22 } //1
		$a_01_2 = {63 61 6c 6c 73 68 65 6c 6c 28 73 74 72 66 69 6c 65 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 65 6c 73 65 65 6e 64 69 66 65 6e 64 73 75 62 } //1 callshell(strfile,vbnormalfocus)elseendifendsub
		$a_01_3 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_RVCM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_03_1 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-64] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 6a ?? 2d 68 ?? ?? 6c ?? ?? 67 2e ?? ?? 6d 2f } //1
		$a_03_2 = {49 6e 53 74 72 28 [0-64] 2c 20 4d 69 64 28 [0-64] 2c 20 69 2c 20 31 29 29 } //1
		$a_01_3 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
		$a_01_4 = {20 3d 20 22 50 6c 65 61 73 65 20 77 61 69 74 22 } //1  = "Please wait"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}