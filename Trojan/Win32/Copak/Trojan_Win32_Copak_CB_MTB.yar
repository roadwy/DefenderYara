
rule Trojan_Win32_Copak_CB_MTB{
	meta:
		description = "Trojan:Win32/Copak.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 13 01 f1 81 c3 04 00 00 00 81 c7 90 02 04 39 c3 75 e7 90 00 } //2
		$a_01_1 = {31 39 01 c2 41 42 89 c2 39 d9 75 dc } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}