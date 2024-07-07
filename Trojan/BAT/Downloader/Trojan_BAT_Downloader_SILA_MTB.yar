
rule Trojan_BAT_Downloader_SILA_MTB{
	meta:
		description = "Trojan:BAT/Downloader.SILA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 63 64 31 38 30 65 66 37 2d 63 66 65 64 2d 34 31 30 63 2d 61 32 39 63 2d 63 35 31 63 31 33 36 36 38 34 31 30 } //10 $cd180ef7-cfed-410c-a29c-c51c13668410
		$a_01_1 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_01_2 = {49 73 4b 65 79 44 6f 77 6e } //1 IsKeyDown
		$a_01_3 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //1 keybd_event
		$a_01_4 = {4b 65 79 50 72 65 73 73 } //1 KeyPress
		$a_01_5 = {46 65 74 63 68 46 69 6c 65 73 } //1 FetchFiles
		$a_01_6 = {49 6e 74 72 6e 65 74 } //1 Intrnet
		$a_01_7 = {4d 65 74 68 6f 64 49 6e 66 6f } //1 MethodInfo
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}