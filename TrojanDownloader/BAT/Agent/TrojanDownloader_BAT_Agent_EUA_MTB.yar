
rule TrojanDownloader_BAT_Agent_EUA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Agent.EUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 7a 00 2e 00 7a 00 7a 00 2e 00 66 00 6f 00 2f 00 73 00 57 00 71 00 4b 00 4f 00 2e 00 62 00 69 00 6e 00 } //1 https://z.zz.fo/sWqKO.bin
		$a_01_1 = {2f 00 53 00 6f 00 75 00 6e 00 64 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2f 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 /SoundService/test.exe
		$a_01_2 = {42 61 6c 43 68 65 63 6b 2e 65 78 65 } //1 BalCheck.exe
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_5 = {24 66 39 31 39 35 33 37 32 2d 66 34 30 66 2d 34 35 38 61 2d 38 37 33 38 2d 39 61 37 30 39 37 38 37 30 31 35 37 } //1 $f9195372-f40f-458a-8738-9a7097870157
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}