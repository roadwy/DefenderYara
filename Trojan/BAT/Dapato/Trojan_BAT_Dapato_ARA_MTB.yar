
rule Trojan_BAT_Dapato_ARA_MTB{
	meta:
		description = "Trojan:BAT/Dapato.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 57 61 6c 6c 70 61 70 65 72 58 2e 70 64 62 } //2 \WallpaperX.pdb
		$a_80_1 = {63 6f 6e 66 69 67 2e 74 78 74 } //config.txt  2
		$a_01_2 = {52 4f 4f 4d 5f 4b 45 59 } //2 ROOM_KEY
		$a_80_3 = {6c 6f 67 2e 74 78 74 } //log.txt  2
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 46 72 6f 6d 55 52 4c } //2 DownloadFileFromURL
		$a_01_5 = {55 70 6c 6f 61 64 44 61 74 61 } //2 UploadData
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}