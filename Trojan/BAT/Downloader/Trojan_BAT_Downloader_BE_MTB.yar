
rule Trojan_BAT_Downloader_BE_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 74 68 65 72 6e 65 74 20 6f 72 20 57 69 46 69 20 4e 65 74 77 6f 72 6b } //1 Ethernet or WiFi Network
		$a_81_1 = {53 70 65 65 64 20 28 62 69 74 73 20 70 65 72 20 73 65 63 6f 6e 64 65 29 } //1 Speed (bits per seconde)
		$a_81_2 = {42 79 74 65 73 52 65 63 65 69 76 65 64 3a 20 7b 30 7d } //1 BytesReceived: {0}
		$a_01_3 = {24 32 66 31 34 66 63 63 62 2d 33 38 62 37 2d 34 66 32 63 2d 38 34 30 66 2d 37 32 36 31 30 39 31 63 37 36 30 63 } //1 $2f14fccb-38b7-4f2c-840f-7261091c760c
		$a_01_4 = {65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //1 edom SOD ni nur eb tonnac margorp sihT!
		$a_81_5 = {4a 46 54 41 79 57 55 70 35 4e } //1 JFTAyWUp5N
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}