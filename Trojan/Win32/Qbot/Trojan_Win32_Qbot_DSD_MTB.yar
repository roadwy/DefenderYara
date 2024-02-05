
rule Trojan_Win32_Qbot_DSD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 2c 3b 30 cd c6 44 24 37 41 8b 7c 24 28 88 2c 17 8b 44 24 38 35 d7 cf c7 0e 89 44 24 38 83 c2 01 8b 44 24 30 39 c2 8b 04 24 89 54 24 18 89 44 24 14 89 74 24 1c 0f 84 } //00 00 
	condition:
		any of ($a_*)
 
}