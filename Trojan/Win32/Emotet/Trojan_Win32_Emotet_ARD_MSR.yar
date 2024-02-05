
rule Trojan_Win32_Emotet_ARD_MSR{
	meta:
		description = "Trojan:Win32/Emotet.ARD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //01 00 
		$a_01_1 = {44 72 6f 70 20 62 6f 6d 62 20 28 70 6f 6f 70 29 3a } //01 00 
		$a_01_2 = {6f 77 6e 65 72 20 64 65 61 64 } //01 00 
		$a_01_3 = {62 72 6f 6b 65 6e 20 70 69 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}