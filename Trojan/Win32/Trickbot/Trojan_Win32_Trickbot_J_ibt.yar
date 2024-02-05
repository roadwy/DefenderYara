
rule Trojan_Win32_Trickbot_J_ibt{
	meta:
		description = "Trojan:Win32/Trickbot.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 40 90 01 01 04 90 01 01 04 90 01 01 04 90 01 01 04 2e 00 65 00 78 00 65 00 90 00 } //05 00 
		$a_02_1 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 40 90 01 01 10 90 01 01 10 90 01 01 10 90 01 01 10 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_02_2 = {68 00 04 00 00 8d 90 02 09 ff 15 90 02 20 ff 15 90 01 04 85 c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}