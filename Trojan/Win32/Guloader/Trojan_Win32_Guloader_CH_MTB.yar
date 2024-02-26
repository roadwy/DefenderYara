
rule Trojan_Win32_Guloader_CH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f4 2d 7a 9e 35 aa 19 cf 2d fd f1 23 2e ec 16 b1 80 74 } //01 00 
		$a_01_1 = {2d 05 78 56 0d fc f1 d3 7f 15 d4 d3 2d fd fa 24 1c bc 7b 20 d7 d4 ab 93 fd } //00 00 
	condition:
		any of ($a_*)
 
}