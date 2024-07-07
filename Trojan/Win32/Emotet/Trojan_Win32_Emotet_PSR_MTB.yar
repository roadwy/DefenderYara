
rule Trojan_Win32_Emotet_PSR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 01 01 03 c2 99 b9 90 01 04 f7 f9 8b 4c 24 90 01 01 8b 44 24 90 01 01 83 c1 01 89 4c 24 90 01 01 8a 54 14 90 01 01 30 54 08 90 00 } //1
		$a_81_1 = {44 4f 6f 4c 65 41 72 76 59 69 30 50 75 74 5a 6b 44 6a 68 54 78 65 59 71 33 7a 44 41 75 62 } //1 DOoLeArvYi0PutZkDjhTxeYq3zDAub
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}