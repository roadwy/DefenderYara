
rule Trojan_Win32_Emotet_TT_MSR{
	meta:
		description = "Trojan:Win32/Emotet.TT!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 2a 30 1c 31 42 3b d7 7c ?? 33 d2 41 3b c8 72 } //1
		$a_00_1 = {68 54 79 76 51 4b 72 6c 49 4c 73 46 62 6f 73 6d 30 63 67 32 77 55 72 45 7a 46 4e 31 36 35 4f } //1 hTyvQKrlILsFbosm0cg2wUrEzFN165O
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}