
rule Trojan_Win32_Spynoon_RM_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 e2 4b b6 00 00 43 ba 5f 7a 01 00 42 25 0e 23 01 00 05 09 f2 00 00 81 fa 2f e1 00 00 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}