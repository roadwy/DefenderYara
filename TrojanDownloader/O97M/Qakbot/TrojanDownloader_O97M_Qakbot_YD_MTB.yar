
rule TrojanDownloader_O97M_Qakbot_YD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.YD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6a 61 62 62 61 2e 66 75 6e 2f 63 72 75 6e 32 30 2e 67 69 66 } //2 http://jabba.fun/crun20.gif
		$a_00_1 = {43 3a 5c 43 4f 73 75 76 5c 57 65 67 65 72 62 5c 73 7a 76 4d 68 65 67 6e 2e 65 78 65 } //1 C:\COsuv\Wegerb\szvMhegn.exe
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}