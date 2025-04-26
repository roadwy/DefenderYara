
rule Trojan_BAT_Spynoon_ARNA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ARNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1b 00 7e 20 00 00 04 06 7e 20 00 00 04 06 91 20 a6 06 00 00 59 d2 9c 00 06 17 58 0a 06 7e 20 00 00 04 8e 69 fe 04 0b 07 2d d7 } //4
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}