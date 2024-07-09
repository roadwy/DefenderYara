
rule Trojan_Win32_Kechang_SR_MSR{
	meta:
		description = "Trojan:Win32/Kechang.SR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 73 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 79 [0-04] 2e 64 61 74 } //1
		$a_02_1 = {56 57 68 58 92 41 00 68 e8 f1 63 00 c7 05 e4 f1 43 00 [0-04] e8 6b 8f 00 00 83 c4 08 8d 44 24 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}