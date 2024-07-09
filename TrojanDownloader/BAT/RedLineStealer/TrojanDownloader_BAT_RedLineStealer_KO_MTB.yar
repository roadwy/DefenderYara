
rule TrojanDownloader_BAT_RedLineStealer_KO_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 72 6f ?? 00 70 17 72 3d ?? 00 70 6f ?? 00 00 06 6f ?? 00 00 06 7d ?? 00 00 04 02 06 07 72 e5 ?? 00 70 17 72 5d ?? 00 70 6f ?? 00 00 06 6f ?? 00 00 06 7d ?? 00 00 04 06 17 1f 64 6a 1f 14 6a 16 6a 6f ?? 00 00 06 0c 08 2c 31 00 06 02 7b } //2
		$a_01_1 = {47 00 65 00 74 00 54 00 79 00 70 00 65 00 } //1 GetType
		$a_01_2 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}