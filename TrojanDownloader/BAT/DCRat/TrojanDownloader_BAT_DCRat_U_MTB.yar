
rule TrojanDownloader_BAT_DCRat_U_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d ?? 00 00 01 0a 03 6f ?? 00 00 0a 0b 16 0c } //2
		$a_01_1 = {06 08 02 08 91 07 08 07 8e 69 5d 93 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*4) >=6
 
}