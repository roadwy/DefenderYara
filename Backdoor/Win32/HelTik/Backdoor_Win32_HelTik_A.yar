
rule Backdoor_Win32_HelTik_A{
	meta:
		description = "Backdoor:Win32/HelTik.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 50 6e 50 5f 4e 6f 5f 4d 61 6e 61 67 65 6d 65 6e 74 00 } //01 00 
		$a_01_1 = {4e 6f 74 20 53 75 70 70 6f 72 74 20 54 68 69 73 20 46 75 6e 63 74 69 6f 6e 21 00 } //02 00 
		$a_01_2 = {c6 85 fd fe ff ff 4d c6 85 fe fe ff ff 49 c6 85 ff fe ff ff 43 c6 85 00 ff ff ff 52 c6 85 01 ff ff ff 30 c6 85 02 ff ff ff 53 c6 85 03 ff ff ff 30 c6 85 04 ff ff ff 46 c6 85 05 ff ff ff 54 } //02 00 
		$a_01_3 = {c6 85 fc fe ff ff 43 c6 85 fd fe ff ff 30 c6 85 fe fe ff ff 52 c6 85 ff fe ff ff 50 c6 85 00 ff ff ff 30 c6 85 01 ff ff ff 52 c6 85 02 ff ff ff 41 c6 85 03 ff ff ff 54 c6 85 04 ff ff ff 49 c6 85 05 ff ff ff 30 c6 85 06 ff ff ff 4e } //01 00 
		$a_01_4 = {49 49 53 43 4d 44 20 45 72 72 6f 72 3a 25 64 0a } //00 00 
	condition:
		any of ($a_*)
 
}