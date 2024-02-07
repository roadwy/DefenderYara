
rule Trojan_Win32_Straba_AST_MTB{
	meta:
		description = "Trojan:Win32/Straba.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {49 67 76 59 62 79 6e } //05 00  IgvYbyn
		$a_01_1 = {4f 6e 62 46 74 76 79 62 } //01 00  OnbFtvyb
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //00 00  GetCurrentThreadId
	condition:
		any of ($a_*)
 
}