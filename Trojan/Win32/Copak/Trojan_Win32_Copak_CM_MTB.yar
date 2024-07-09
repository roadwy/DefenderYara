
rule Trojan_Win32_Copak_CM_MTB{
	meta:
		description = "Trojan:Win32/Copak.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 d3 31 0f 4a 89 d3 47 09 da 39 f7 75 e3 } //2
		$a_03_1 = {8b 0c 24 83 c4 04 e8 [0-04] 31 0f 4a 81 c7 01 00 00 00 39 f7 75 de } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}