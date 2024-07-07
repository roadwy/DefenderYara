
rule Trojan_Win32_Beerish_O_dha{
	meta:
		description = "Trojan:Win32/Beerish.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 01 68 02 00 00 80 e8 90 01 03 00 83 c4 08 a3 90 01 04 6a 02 68 02 00 00 80 e8 90 01 03 00 83 c4 08 a3 90 01 04 6a 03 68 02 00 00 80 90 00 } //1
		$a_03_1 = {ba 01 00 00 00 b9 02 00 00 80 e8 90 01 03 00 48 90 01 06 ba 02 00 00 00 b9 02 00 00 80 e8 90 01 03 00 48 90 01 06 ba 03 00 00 00 b9 02 00 00 80 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}