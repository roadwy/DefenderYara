
rule Trojan_Win64_Dridex_RPY_MTB{
	meta:
		description = "Trojan:Win64/Dridex.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 40 48 8b 4c 24 58 48 8b 54 24 18 44 8a 04 0a 25 ff 00 00 00 89 c0 89 c1 4c 8b 4c 24 10 45 32 04 09 48 8b 4c 24 58 4c 8b 54 24 28 45 88 04 0a 48 8b 4c 24 58 48 83 c1 01 4c 8b 5c 24 30 48 89 4c 24 50 8b 44 24 44 89 44 24 4c } //00 00 
	condition:
		any of ($a_*)
 
}