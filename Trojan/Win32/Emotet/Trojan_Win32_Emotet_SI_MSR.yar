
rule Trojan_Win32_Emotet_SI_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 00 62 00 63 00 67 00 64 00 66 00 61 00 73 00 7a 00 78 00 64 00 64 00 66 00 65 00 72 00 71 00 61 00 73 00 77 00 } //1 vbcgdfaszxddferqasw
		$a_01_1 = {64 72 6f 70 20 69 6e 74 6f 20 77 69 6e 64 6f 77 } //1 drop into window
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}