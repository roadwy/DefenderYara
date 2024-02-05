
rule Trojan_Win32_Dogrobot_gen_B{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00 } //01 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 45 00 44 00 49 00 53 00 4b 00 } //05 00 
		$a_01_2 = {8b 75 0c 8b 46 60 81 78 0c 04 28 40 9c 57 89 4d fc 74 1a } //00 00 
	condition:
		any of ($a_*)
 
}