
rule TrojanDownloader_BAT_AsyncRAT_ELM_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.ELM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 6f 6f 6b 69 6e 67 73 5f 30 35 36 5f 30 37 2e 65 78 65 } //1 Bookings_056_07.exe
		$a_81_1 = {48 65 6c 70 66 65 65 6c 20 49 6e 63 } //2 Helpfeel Inc
		$a_81_2 = {47 79 61 7a 6f 3a 20 53 63 72 65 65 6e 20 55 70 6c 6f 61 64 65 72 } //1 Gyazo: Screen Uploader
		$a_81_3 = {68 74 74 70 3a 2f 2f 31 34 34 2e 31 37 32 2e 31 31 36 2e 31 32 31 2f 75 69 75 2f 41 77 75 6f 6c 61 76 65 65 2e 6d 70 33 } //2 http://144.172.116.121/uiu/Awuolavee.mp3
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2) >=6
 
}