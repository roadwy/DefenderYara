
rule Trojan_Win64_CobaltStrike_UP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.UP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d0 44 0f af 43 44 0f af d0 48 8b 83 a8 00 00 00 89 93 98 00 00 00 41 8b d0 c1 ea 10 88 14 01 b8 24 fa 14 00 2b 43 58 41 8b d0 } //01 00 
		$a_01_1 = {41 8b 81 8c 00 00 00 41 29 81 e4 00 00 00 41 8b 41 68 49 8b 89 b8 00 00 00 31 04 11 } //00 00 
	condition:
		any of ($a_*)
 
}