
rule Trojan_Win64_CobaltStrike_WS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 85 c0 0f 84 91 00 00 00 83 b8 18 01 00 00 0a 0f 85 84 00 00 00 48 8b 40 18 48 8b 48 20 48 8b 01 4c 8b 50 20 } //01 00 
		$a_01_1 = {50 72 65 73 73 20 3c 45 6e 74 65 72 3e 20 54 6f 20 45 78 65 63 75 74 65 20 54 68 65 20 50 61 79 6c 6f 61 64 20 2e 2e 2e } //00 00  Press <Enter> To Execute The Payload ...
	condition:
		any of ($a_*)
 
}