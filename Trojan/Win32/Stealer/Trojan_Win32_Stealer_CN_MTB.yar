
rule Trojan_Win32_Stealer_CN_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 e9 81 c1 90 01 04 33 31 89 ef 81 c7 90 01 04 2b 37 89 eb 81 c3 90 01 04 31 33 89 e8 90 00 } //1
		$a_03_1 = {31 18 89 e8 05 90 01 04 81 00 90 01 04 89 ea 81 c2 90 01 04 8a 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}