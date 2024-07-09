
rule Trojan_Win32_Copak_CP_MTB{
	meta:
		description = "Trojan:Win32/Copak.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0a 4b 68 [0-04] 5b 81 c2 01 00 00 00 81 e8 [0-04] 09 c3 39 fa 75 ce } //2
		$a_03_1 = {31 08 81 ea [0-04] 81 c6 [0-04] 81 c0 01 00 00 00 01 f2 81 ea [0-04] 39 f8 75 d2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}