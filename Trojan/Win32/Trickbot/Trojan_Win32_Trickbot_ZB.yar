
rule Trojan_Win32_Trickbot_ZB{
	meta:
		description = "Trojan:Win32/Trickbot.ZB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 72 61 62 62 65 72 20 61 74 74 65 6d 70 74 2e } //02 00  Grabber attempt.
		$a_01_1 = {43 6f 75 6c 64 20 6e 6f 74 20 67 61 74 68 65 72 20 62 72 6f 77 73 65 72 20 64 61 74 61 } //02 00  Could not gather browser data
		$a_01_2 = {67 72 61 62 62 65 72 5f 74 65 6d 70 2e 65 64 62 } //03 00  grabber_temp.edb
		$a_01_3 = {2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 } //00 00 
		$a_00_4 = {5d 04 00 00 } //94 51 
	condition:
		any of ($a_*)
 
}