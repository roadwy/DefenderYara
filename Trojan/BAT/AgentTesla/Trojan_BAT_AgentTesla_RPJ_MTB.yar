
rule Trojan_BAT_AgentTesla_RPJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 18 9a 20 d4 01 00 00 95 80 0a 00 00 04 7e 01 00 00 04 19 90 01 02 9a 1f 2c 8f 05 00 00 01 25 71 05 00 00 01 90 01 02 7e 01 00 00 04 18 9a 20 9b 02 00 00 95 61 81 05 00 00 01 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {64 00 65 00 72 00 61 00 5f 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 6a 00 70 00 67 00 } //01 00  dera_crypted.jpg
		$a_01_2 = {46 00 7a 00 71 00 71 00 65 00 71 00 74 00 6e 00 6f 00 73 00 72 00 63 00 61 00 73 00 62 00 70 00 6b 00 72 00 } //01 00  Fzqqeqtnosrcasbpkr
		$a_01_3 = {2d 00 65 00 6e 00 63 00 20 00 59 00 77 00 42 00 74 00 41 00 47 00 51 00 41 00 49 00 41 00 41 00 76 00 41 00 47 00 4d 00 41 00 49 00 41 00 42 00 30 00 41 00 47 00 6b 00 41 00 62 00 51 00 42 00 6c 00 41 00 47 00 38 00 41 00 64 00 51 00 42 00 30 00 41 00 43 00 41 00 41 00 4d 00 67 00 41 00 77 00 41 00 41 00 } //01 00  -enc YwBtAGQAIAAvAGMAIAB0AGkAbQBlAG8AdQB0ACAAMgAwAA
		$a_01_4 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //00 00  powershell
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 23 00 00 00 00 00 88 d3 40 73 1f 00 00 0a 0a 06 02 fe 06 06 00 00 06 73 20 00 00 0a 6f 21 00 00 0a 00 06 17 6f 22 00 00 0a 00 06 16 6f 23 00 00 0a 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}