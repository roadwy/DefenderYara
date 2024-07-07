
rule TrojanDownloader_BAT_Banload_ABL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Banload.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 0b 2b 1a 11 15 11 0b 9a 13 16 11 16 17 28 90 01 03 0a de 03 26 de 00 11 0b 17 58 13 0b 11 0b 11 15 8e 69 32 de 90 00 } //2
		$a_01_1 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 47 73 6d 52 65 6d 6f 74 65 53 65 72 76 69 63 65 5c 47 73 6d 52 65 6d 6f 74 65 53 65 72 76 69 63 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 47 73 6d 52 65 6d 6f 74 65 53 65 72 76 69 63 65 2e 70 64 62 } //1 source\repos\GsmRemoteService\GsmRemoteService\obj\Release\GsmRemoteService.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}