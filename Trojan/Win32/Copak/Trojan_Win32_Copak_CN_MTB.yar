
rule Trojan_Win32_Copak_CN_MTB{
	meta:
		description = "Trojan:Win32/Copak.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 1e 01 c0 46 39 fe 75 ed } //2
		$a_03_1 = {31 3a 81 c2 01 00 00 00 29 c0 81 e8 90 02 04 39 ca 75 da 90 00 } //2
		$a_03_2 = {31 0a 81 c6 90 02 04 47 42 39 c2 75 d9 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}