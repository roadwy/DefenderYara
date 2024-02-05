
rule Trojan_Win32_Trickbot_DHB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 89 45 00 ff 15 90 01 04 8b 55 00 8b 44 24 90 01 01 6a 00 6a 00 56 52 6a 01 50 53 ff d7 90 00 } //01 00 
		$a_02_1 = {83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3 8b 4c 24 90 01 01 8b 54 24 90 01 01 51 8b f0 52 56 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}