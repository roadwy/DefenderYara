
rule Trojan_Win32_Pikabot_MMC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c } //01 00 
		$a_01_1 = {8d 40 0c 8b 00 8b 40 18 } //00 00 
	condition:
		any of ($a_*)
 
}