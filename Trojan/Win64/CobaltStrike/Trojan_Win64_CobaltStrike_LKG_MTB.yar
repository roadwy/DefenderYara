
rule Trojan_Win64_CobaltStrike_LKG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 47 58 48 81 c9 2b 4b 00 00 48 0f af c1 48 89 47 58 b8 c1 41 00 00 48 2b 87 18 01 00 00 48 01 87 80 00 00 00 45 85 c9 } //01 00 
		$a_01_1 = {48 31 4e 58 41 8b c9 d3 ea 8a 48 40 48 8b 46 20 80 f1 a0 22 d1 48 63 8e 10 01 00 00 88 14 01 ff 86 10 01 00 00 45 85 c9 } //00 00 
	condition:
		any of ($a_*)
 
}