
rule Trojan_Win32_Copak_DF_MTB{
	meta:
		description = "Trojan:Win32/Copak.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 02 01 f1 81 c2 04 00 00 00 39 fa 75 ed } //1
		$a_01_1 = {52 51 58 29 c8 5f 40 43 21 c9 81 fb 94 12 00 01 75 b2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}