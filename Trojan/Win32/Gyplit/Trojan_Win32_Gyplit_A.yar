
rule Trojan_Win32_Gyplit_A{
	meta:
		description = "Trojan:Win32/Gyplit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 10 32 d9 88 1c 10 40 3b c6 7c cc } //1
		$a_03_1 = {74 52 b9 11 00 00 00 33 c0 8d 7c 24 90 01 01 8d 54 24 90 01 01 f3 ab 90 00 } //1
		$a_01_2 = {8a 9c 04 bc 02 00 00 80 f3 47 88 9c 04 bc 02 00 00 40 3b c1 72 ea 8d 4c 24 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}