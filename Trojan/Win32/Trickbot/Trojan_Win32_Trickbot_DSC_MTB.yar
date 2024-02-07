
rule Trojan_Win32_Trickbot_DSC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 19 84 db 74 90 01 01 8a fb 80 c7 bf 80 ff 19 77 90 01 01 8a fb 80 f3 20 80 e7 20 0a df 88 19 4a 41 48 3b d6 7f 90 00 } //01 00 
		$a_00_1 = {5a 58 70 4d 5a 58 34 53 2b 72 38 70 50 59 56 4f 50 58 38 70 6e 42 71 30 5a 58 47 34 } //00 00  ZXpMZX4S+r8pPYVOPX8pnBq0ZXG4
	condition:
		any of ($a_*)
 
}