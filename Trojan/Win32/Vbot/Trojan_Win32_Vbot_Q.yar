
rule Trojan_Win32_Vbot_Q{
	meta:
		description = "Trojan:Win32/Vbot.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 45 6d 61 69 6c 73 00 69 44 6f 6e 77 45 78 65 63 } //01 00 
		$a_01_1 = {49 6e 66 65 63 59 6f 75 00 } //01 00 
		$a_01_2 = {48 6f 73 44 61 74 6f 73 5f 4f 4e 00 } //01 00 
		$a_00_3 = {50 00 61 00 73 00 77 00 3a 00 } //00 00 
	condition:
		any of ($a_*)
 
}