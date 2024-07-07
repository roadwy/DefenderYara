
rule Trojan_Win32_Razy_CJ_MTB{
	meta:
		description = "Trojan:Win32/Razy.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 01 ea 31 19 48 81 ef 90 02 04 81 c1 04 00 00 00 39 d1 75 e8 90 00 } //2
		$a_03_1 = {01 ea 31 1e 09 c9 81 ea 90 02 04 81 c6 04 00 00 00 21 d2 39 fe 75 e5 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}