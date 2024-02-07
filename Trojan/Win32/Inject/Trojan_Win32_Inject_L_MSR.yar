
rule Trojan_Win32_Inject_L_MSR{
	meta:
		description = "Trojan:Win32/Inject.L!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 49 6b 4f 34 79 37 39 54 31 6c 65 4b 73 79 34 66 69 51 63 44 49 49 73 55 32 69 33 78 49 68 52 } //01 00  PIkO4y79T1leKsy4fiQcDIIsU2i3xIhR
		$a_81_1 = {50 72 6f 63 65 73 73 49 6e 6a 65 63 74 69 6f 6e } //01 00  ProcessInjection
		$a_81_2 = {53 68 65 6c 6c 63 6f 64 65 44 65 6c 65 67 61 74 65 } //00 00  ShellcodeDelegate
	condition:
		any of ($a_*)
 
}