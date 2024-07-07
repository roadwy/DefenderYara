
rule Trojan_Win32_Emotet_HC_MSR{
	meta:
		description = "Trojan:Win32/Emotet.HC!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 e9 59 11 00 00 89 0d cc 5f 44 00 8b 0d cc 5f 44 00 81 c1 59 11 00 00 a1 d0 5f 44 00 a3 d4 5f 44 00 b8 c9 ee 06 00 b8 c9 ee 06 } //1
		$a_01_1 = {b8 c9 ee 06 00 b8 c9 ee 06 00 b8 c9 ee 06 00 b8 c9 ee 06 00 a1 d4 5f 44 00 31 0d d4 5f 44 00 8b ff c7 05 d0 5f 44 00 00 00 00 00 a1 d4 5f 44 00 01 05 d0 5f 44 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}