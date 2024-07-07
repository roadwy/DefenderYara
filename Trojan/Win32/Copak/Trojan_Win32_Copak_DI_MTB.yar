
rule Trojan_Win32_Copak_DI_MTB{
	meta:
		description = "Trojan:Win32/Copak.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 c6 c4 a0 f4 6c 31 11 50 5e 81 e8 4e 04 d1 c2 81 c1 01 00 00 00 21 f6 39 f9 75 } //1
		$a_01_1 = {89 cf 43 81 e9 f5 13 37 11 01 ff 81 fb ee 8e 00 01 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}