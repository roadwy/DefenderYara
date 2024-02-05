
rule Trojan_Win32_Glowroni{
	meta:
		description = "Trojan:Win32/Glowroni,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 75 62 6f 65 65 67 79 } //02 00 
		$a_01_1 = {6d 61 73 6b 65 72 6f 6e 69 2e 63 6f 2e 75 6b } //01 00 
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c } //01 00 
		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 63 63 45 76 74 4d 67 72 } //02 00 
		$a_01_4 = {6a 6f 69 6e 63 67 75 69 2e 64 6c 6c } //02 00 
		$a_01_5 = {67 6c 6f 77 65 78 74 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}