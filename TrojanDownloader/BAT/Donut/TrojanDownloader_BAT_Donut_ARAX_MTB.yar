
rule TrojanDownloader_BAT_Donut_ARAX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Donut.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 39 39 33 36 37 61 62 35 2d 62 63 64 31 2d 34 32 63 34 2d 62 31 34 35 2d 38 36 64 66 64 35 63 36 35 34 34 36 } //2 $99367ab5-bcd1-42c4-b145-86dfd5c65446
		$a_00_1 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //2 update.exe
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_3 = {48 74 74 70 52 65 73 70 6f 6e 73 65 4d 65 73 73 61 67 65 } //1 HttpResponseMessage
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}