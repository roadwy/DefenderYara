
rule TrojanDownloader_BAT_RedLineStealer_KN_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 12 01 28 ?? 00 00 0a 7e ?? 00 00 04 02 28 ?? 00 00 0a 0c 08 7e ?? 00 00 04 6f ?? 00 00 0a 3c ?? 00 00 00 7e ?? 00 00 04 08 6f ?? 00 00 0a 02 40 ?? 00 00 00 7e ?? 00 00 04 08 6f ?? 00 00 0a 0d dd } //2
		$a_01_1 = {01 13 04 7e 05 00 00 04 02 1a 58 11 04 16 08 28 1c 00 00 0a 28 18 00 00 0a 11 04 16 11 04 8e 69 6f 5f 00 00 0a 13 05 7e 04 00 00 04 11 05 6f 60 00 00 0a 7e 2b 00 00 04 02 6f 61 00 00 0a 7e 04 00 00 04 6f 62 00 00 0a 17 59 28 63 00 00 0a 16 7e 05 00 00 04 02 1a 28 1c 00 00 0a 11 05 0d dd } //2
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_3 = {50 72 6f 63 65 73 73 } //1 Process
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}