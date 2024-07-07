
rule TrojanDownloader_BAT_DiscordStealer_PAX_MTB{
	meta:
		description = "TrojanDownloader:BAT/DiscordStealer.PAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 73 19 00 00 0a 20 e3 07 cd 04 6f 90 01 03 0a 0b 07 8e 16 fe 03 2c 11 06 07 6f 90 01 03 0a 06 6f 90 01 03 0a 06 0c 2b 02 14 0c 08 2a 90 00 } //1
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}