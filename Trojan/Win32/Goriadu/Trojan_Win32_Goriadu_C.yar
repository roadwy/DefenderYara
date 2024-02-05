
rule Trojan_Win32_Goriadu_C{
	meta:
		description = "Trojan:Win32/Goriadu.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 79 54 6f 6f 6c 73 48 65 6c 70 5c } //02 00 
		$a_01_1 = {25 73 5c 53 4e 31 5f 25 64 5f 25 64 2e 6c 6f 67 } //02 00 
		$a_01_2 = {73 70 5f 72 65 67 74 61 62 6c 65 5f 6d 75 74 65 78 33 32 } //03 00 
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 57 69 6e 53 6f 63 6b 32 5c 73 70 65 65 64 6e 65 74 5f 73 70 68 } //00 00 
	condition:
		any of ($a_*)
 
}