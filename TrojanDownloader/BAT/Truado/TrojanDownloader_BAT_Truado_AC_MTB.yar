
rule TrojanDownloader_BAT_Truado_AC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Truado.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 05 20 09 ?? ?? 00 28 20 ?? ?? 06 3a 5a ?? ?? 00 38 55 ?? ?? 00 08 28 25 ?? ?? 06 28 26 ?? ?? 06 73 2f ?? ?? 0a 0d 20 06 ?? ?? 00 38 3a ?? ?? 00 00 72 79 ?? ?? 70 72 d8 ?? ?? 70 72 f0 ?? ?? 70 28 21 ?? ?? 06 0a 20 07 ?? ?? 00 38 1a ?? ?? 00 00 07 28 24 ?? ?? 06 0c 38 b8 ?? ?? ff 20 01 ?? ?? 00 fe 0e ?? 00 fe 0c 06 00 } //4
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}