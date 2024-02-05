
rule Trojan_Win32_Coroxy_MA_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 07 d2 f1 fe c1 81 c7 04 00 00 00 66 0f 43 ce 33 c3 0f ac ea 3a f7 d8 80 c5 2f d2 e9 d3 e1 35 } //05 00 
		$a_01_1 = {e9 1a 93 46 00 8b 0f 81 c7 04 00 00 00 33 cb d1 c9 99 81 e9 2e 16 83 7d c1 c9 03 49 03 c6 33 d9 } //02 00 
		$a_01_2 = {72 75 6e 64 6c 6c } //02 00 
		$a_01_3 = {47 65 74 55 73 65 72 4e 61 6d 65 45 78 41 } //02 00 
		$a_01_4 = {73 6f 63 6b 73 33 32 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}