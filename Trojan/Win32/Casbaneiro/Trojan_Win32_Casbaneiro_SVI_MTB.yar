
rule Trojan_Win32_Casbaneiro_SVI_MTB{
	meta:
		description = "Trojan:Win32/Casbaneiro.SVI!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 55 47 48 46 44 52 75 75 47 42 48 55 37 42 4b 4a 42 } //2 bUGHFDRuuGBHU7BKJB
		$a_01_1 = {24 5a 58 77 52 } //2 $ZXwR
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}