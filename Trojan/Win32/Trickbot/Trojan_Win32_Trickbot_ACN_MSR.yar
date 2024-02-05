
rule Trojan_Win32_Trickbot_ACN_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.ACN!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {3a 5c 42 75 79 5c 73 74 6f 72 65 5c 6b 69 6e 67 5c 46 65 77 5c 43 68 61 6e 67 65 90 02 14 5c 4f 63 65 61 6e 66 75 6e 2e 70 64 62 90 00 } //01 00 
		$a_00_1 = {63 61 6e 70 61 72 65 6e 74 2e 64 6c 6c } //01 00 
		$a_00_2 = {74 65 6d 70 6c 2e 64 6c 6c } //01 00 
		$a_00_3 = {00 45 52 4e 45 4c 33 32 2e 64 6c 6c } //01 00 
		$a_00_4 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 77 65 6e 74 73 70 65 6e 64 2e 72 75 2f } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}