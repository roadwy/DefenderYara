
rule Trojan_Win32_Trickbot_ZZ_ST{
	meta:
		description = "Trojan:Win32/Trickbot.ZZ!ST,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 f2 ff 00 00 89 45 04 59 8b d7 49 8b f2 49 90 09 05 00 05 90 00 } //02 00 
		$a_03_1 = {e8 00 00 00 00 58 89 c3 05 3a 05 00 00 81 c3 90 01 04 68 01 00 00 00 68 05 00 00 00 53 68 45 77 62 30 50 e8 04 00 00 00 83 c4 14 c3 83 ec 48 83 64 24 18 00 b9 4c 77 26 07 90 00 } //01 00 
		$a_01_2 = {8b 74 24 10 8b 44 16 24 8d 04 58 0f b7 0c 10 8b 44 16 1c 8d 04 88 8b 04 10 03 c2 eb db 4d 5a 80 } //01 00 
		$a_03_3 = {8d 40 00 00 00 00 90 02 20 05 8b ff 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}