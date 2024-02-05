
rule Trojan_Win32_Lokibot_AA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 2d b1 30 14 67 05 b5 b9 c0 2b a6 82 79 16 b0 f7 85 e2 2c f9 82 fc 41 f9 3e 7d 6c 1b 3b 79 e0 } //00 00 
	condition:
		any of ($a_*)
 
}