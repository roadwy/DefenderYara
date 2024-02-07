
rule Trojan_Win32_Qakbot_RPO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //01 00  VisibleEntry
		$a_01_1 = {62 61 6e 61 67 6f } //01 00  banago
		$a_01_2 = {64 65 66 61 75 6c 74 75 72 65 } //01 00  defaulture
		$a_01_3 = {65 70 69 63 6f 72 6f 6c 6c 69 6e 65 } //01 00  epicorolline
		$a_01_4 = {65 78 69 73 74 65 6e 74 69 61 6c 69 73 74 } //01 00  existentialist
		$a_01_5 = {68 79 70 6f 70 68 61 72 79 6e 67 65 61 6c } //01 00  hypopharyngeal
		$a_01_6 = {6e 69 63 65 6e 69 61 6e } //01 00  nicenian
		$a_01_7 = {73 6c 61 76 65 6c 61 6e 64 } //01 00  slaveland
		$a_01_8 = {76 69 6f 6c 65 74 77 69 73 65 } //00 00  violetwise
	condition:
		any of ($a_*)
 
}