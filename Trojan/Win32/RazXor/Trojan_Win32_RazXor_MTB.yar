
rule Trojan_Win32_RazXor_MTB{
	meta:
		description = "Trojan:Win32/RazXor!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 34 30 01 d2 8b 36 81 ea 90 01 04 81 e6 ff 00 00 00 09 ca 40 49 01 c9 81 f8 f4 01 00 00 75 90 02 01 b8 00 00 00 00 90 00 } //1
		$a_01_1 = {81 c1 01 00 00 00 31 33 81 c3 01 00 00 00 39 fb 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}