
rule Trojan_Win32_Copak_CQ_MTB{
	meta:
		description = "Trojan:Win32/Copak.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 0b 09 d2 81 e8 90 02 04 81 c3 04 00 00 00 81 c2 90 02 04 39 f3 75 e1 90 00 } //2
		$a_03_1 = {31 16 09 c8 81 c3 90 02 04 81 c6 04 00 00 00 39 fe 75 e7 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}