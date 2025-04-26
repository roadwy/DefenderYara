
rule Trojan_Win64_Sliver_A_MTB{
	meta:
		description = "Trojan:Win64/Sliver.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8b 20 01 00 00 2b 4b 74 81 c1 1d 14 00 00 89 4b 64 8b 83 f8 00 00 00 39 83 04 01 00 00 73 0d 8b 43 2c 35 1b 14 00 00 2b c8 89 4b 64 48 8b 05 0a 28 6b 00 44 8d ?? ?? 83 f7 38 48 89 05 ec 27 6b 00 45 8b cf 48 89 5c 24 20 8b cf 41 8d ?? ?? 41 81 f1 de 03 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}