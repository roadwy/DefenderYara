
rule Trojan_Win32_Trickbot_RA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 84 05 c0 f6 ff ff 40 3b c6 72 } //01 00 
		$a_03_1 = {8a 8c 15 c0 f6 ff ff 30 08 40 83 90 02 1f 0f 90 0a 2f 00 0f b6 07 90 02 0a 99 90 02 0a f7 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}