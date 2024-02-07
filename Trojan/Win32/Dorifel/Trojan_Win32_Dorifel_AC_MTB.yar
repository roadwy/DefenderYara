
rule Trojan_Win32_Dorifel_AC_MTB{
	meta:
		description = "Trojan:Win32/Dorifel.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 31 d2 f7 f3 0f b6 04 17 30 04 0e 41 8b 35 90 02 04 3b 0d 90 02 04 72 d7 90 00 } //01 00 
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}