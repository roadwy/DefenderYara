
rule TrojanDownloader_BAT_Androm_SIB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Androm.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 "
		
	strings :
		$a_02_0 = {16 6a 0a 16 0b 2b ?? 02 6f ?? ?? ?? ?? 0c 06 08 d2 6e 1e 07 5a 1f ?? 5f 62 60 0a 07 17 58 0b 07 1e 32 ?? 06 } //10
		$a_80_1 = {41 4c 41 52 49 43 20 4c 6f 61 64 65 72 2e 65 78 65 } //ALARIC Loader.exe  1
		$a_02_2 = {73 00 74 00 75 00 62 00 5f 00 [0-10] 2e 00 [0-10] 72 00 73 00 72 00 63 00 } //1
		$a_02_3 = {73 74 75 62 5f [0-10] 2e [0-10] 72 73 72 63 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=11
 
}