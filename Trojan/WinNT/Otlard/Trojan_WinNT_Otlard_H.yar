
rule Trojan_WinNT_Otlard_H{
	meta:
		description = "Trojan:WinNT/Otlard.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 32 66 25 01 f0 48 66 81 38 4d 5a 75 f4 } //1
		$a_01_1 = {c1 c2 03 32 10 40 80 38 00 } //1
		$a_01_2 = {6a 2e 58 6a 73 66 89 45 f4 58 6a 79 66 89 45 f6 58 66 89 45 f8 6a 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}