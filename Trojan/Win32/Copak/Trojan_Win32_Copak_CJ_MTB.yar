
rule Trojan_Win32_Copak_CJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 03 81 c7 [0-04] 43 81 c7 [0-04] 39 d3 75 dd } //2
		$a_01_1 = {31 01 41 39 f1 75 e5 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}