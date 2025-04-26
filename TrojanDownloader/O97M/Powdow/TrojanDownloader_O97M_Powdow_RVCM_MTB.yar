
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