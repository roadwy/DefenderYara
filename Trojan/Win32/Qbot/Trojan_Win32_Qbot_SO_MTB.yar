
rule Trojan_Win32_Qbot_SO_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 89 08 c7 80 90 01 04 01 00 00 00 57 8b 90 90 90 01 04 8d 0c 90 90 8b 71 fc 8b fe c1 ef 90 01 01 33 fe 69 ff 90 01 04 03 fa 89 39 ff 80 90 01 04 81 b8 90 01 04 90 01 02 00 00 7c d1 5f 5e c3 90 00 } //01 00 
		$a_03_1 = {8d 0c 10 8d 1c 0f 83 e3 90 01 01 8a 9b 90 01 04 32 1c 16 42 88 19 3b 55 fc 72 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}