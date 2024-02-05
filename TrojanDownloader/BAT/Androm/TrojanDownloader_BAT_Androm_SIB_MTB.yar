
rule TrojanDownloader_BAT_Androm_SIB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Androm.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {16 6a 0a 16 0b 2b 90 01 01 02 6f 90 01 04 0c 06 08 d2 6e 1e 07 5a 1f 90 01 01 5f 62 60 0a 07 17 58 0b 07 1e 32 90 01 01 06 90 00 } //01 00 
		$a_80_1 = {41 4c 41 52 49 43 20 4c 6f 61 64 65 72 2e 65 78 65 } //ALARIC Loader.exe  01 00 
		$a_02_2 = {73 00 74 00 75 00 62 00 5f 00 90 02 10 2e 00 90 02 10 72 00 73 00 72 00 63 00 90 00 } //01 00 
		$a_02_3 = {73 74 75 62 5f 90 02 10 2e 90 02 10 72 73 72 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}