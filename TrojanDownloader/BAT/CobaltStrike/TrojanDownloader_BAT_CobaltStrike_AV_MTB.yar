
rule TrojanDownloader_BAT_CobaltStrike_AV_MTB{
	meta:
		description = "TrojanDownloader:BAT/CobaltStrike.AV!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 00 33 00 34 00 2e 00 31 00 32 00 32 00 2e 00 31 00 37 00 36 00 2e 00 31 00 35 00 36 00 } //2 134.122.176.156
		$a_01_1 = {42 00 79 00 50 00 61 00 73 00 73 00 62 00 62 00 62 00 } //1 ByPassbbb
		$a_01_2 = {6c 00 38 00 62 00 72 00 6d 00 4a 00 53 00 41 00 37 00 39 00 74 00 63 00 36 00 7a 00 30 00 31 00 75 00 67 00 42 00 75 00 74 00 67 00 3d 00 3d 00 } //1 l8brmJSA79tc6z01ugButg==
		$a_01_3 = {43 00 4f 00 4d 00 5f 00 53 00 75 00 72 00 72 00 6f 00 67 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //2 COM_Surrogate.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}