
rule Trojan_Win32_Copak_CH_MTB{
	meta:
		description = "Trojan:Win32/Copak.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 37 89 c3 47 01 db b8 [0-04] 39 d7 75 e6 } //2
		$a_01_1 = {21 df 31 0e 43 09 df 46 4f 29 db 39 d6 75 d9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}