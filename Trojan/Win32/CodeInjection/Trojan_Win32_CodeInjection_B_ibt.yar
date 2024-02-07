
rule Trojan_Win32_CodeInjection_B_ibt{
	meta:
		description = "Trojan:Win32/CodeInjection.B!ibt,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 54 68 65 52 69 67 68 74 50 49 44 } //01 00  FindTheRightPID
		$a_01_1 = {4e 74 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //01 00  NtCreateSection
		$a_01_2 = {4e 74 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  NtMapViewOfSection
		$a_01_3 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 } //01 00  NtCreateThreadEx
		$a_01_4 = {4e 74 4f 70 65 6e 50 72 6f 63 65 73 73 } //00 00  NtOpenProcess
	condition:
		any of ($a_*)
 
}