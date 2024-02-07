
rule Trojan_Win32_Adclicker_O{
	meta:
		description = "Trojan:Win32/Adclicker.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_09_0 = {48 45 52 45 49 53 42 4f 4f 54 43 4f 44 45 } //01 00  HEREISBOOTCODE
		$a_09_1 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 90 00 00 77 73 70 72 69 6e 74 66 41 00 00 00 52 65 67 43 6c 6f 73 65 4b 65 79 } //01 00 
		$a_09_2 = {56 87 1b 2e 00 00 00 00 ff ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}