
rule Trojan_Win64_CobaltStrike_PCE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PCE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 83 68 01 00 00 41 b9 33 36 00 00 48 8b 8b 80 01 00 00 45 8b 1c 00 49 8b 06 48 33 c5 48 01 41 58 8b 83 40 01 00 00 44 0f af 9b 30 01 00 00 05 4c 03 00 00 44 8b 93 64 01 00 00 41 3b c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}