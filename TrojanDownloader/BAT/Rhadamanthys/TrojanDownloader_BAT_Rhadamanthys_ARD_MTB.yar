
rule TrojanDownloader_BAT_Rhadamanthys_ARD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Rhadamanthys.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 05 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de d6 } //1
		$a_01_1 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}