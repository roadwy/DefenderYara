
rule Trojan_Win32_Razy_CG_MTB{
	meta:
		description = "Trojan:Win32/Razy.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 f6 74 01 ea 31 38 81 c1 [0-04] 81 c0 04 00 00 00 49 39 d8 75 e8 } //2
		$a_03_1 = {31 1a 83 ec 04 c7 04 24 [0-04] 5f 29 c1 81 c2 04 00 00 00 39 f2 75 e2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}