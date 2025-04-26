
rule Trojan_Win32_Razy_CQ_MTB{
	meta:
		description = "Trojan:Win32/Razy.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 d7 31 0b 43 68 [0-04] 8b 3c 24 83 c4 04 81 c2 [0-04] 39 c3 75 d0 } //2
		$a_01_1 = {31 08 01 ff 40 21 df 21 df 39 f0 75 d7 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}