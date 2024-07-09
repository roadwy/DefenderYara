
rule Trojan_Win32_Winnti_N_dha{
	meta:
		description = "Trojan:Win32/Winnti.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b1 99 75 15 33 c0 85 f6 7e 0f 8a 14 18 32 d1 fe c1 88 14 18 40 3b c6 7c f1 } //1
		$a_03_1 = {8a 04 31 34 [0-01] 8a d0 c0 e2 04 c0 e8 04 02 d0 88 14 31 8b 45 00 41 3b c8 72 e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}