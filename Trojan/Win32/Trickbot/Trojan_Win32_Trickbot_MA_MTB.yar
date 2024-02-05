
rule Trojan_Win32_Trickbot_MA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 14 03 83 c3 04 8b 46 2c 0f af 56 54 05 0e 19 07 00 09 46 18 8b 46 70 8b 8e 94 00 00 00 88 14 01 ff 46 70 8b 46 20 } //00 00 
	condition:
		any of ($a_*)
 
}