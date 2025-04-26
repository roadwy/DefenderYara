
rule TrojanDownloader_BAT_Tnega_SRPC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tnega.SRPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 73 38 00 00 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 73 26 00 00 0a 0c 73 26 00 00 0a 0d 07 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 16 6a 31 33 08 6f ?? ?? ?? 0a 13 04 08 6f ?? ?? ?? 0a 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 16 6a 31 0e 11 04 2c 0a 09 6f ?? ?? ?? 0a 13 05 } //2
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 36 00 2e 00 37 00 31 00 2e 00 31 00 32 00 30 00 2f 00 46 00 6f 00 70 00 75 00 65 00 74 00 67 00 6c 00 2e 00 62 00 6d 00 70 00 } //1 185.216.71.120/Fopuetgl.bmp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}