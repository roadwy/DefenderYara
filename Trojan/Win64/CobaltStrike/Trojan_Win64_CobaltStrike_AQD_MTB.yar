
rule Trojan_Win64_CobaltStrike_AQD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c1 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 89 44 24 10 8b 44 24 0c 48 63 4c 24 10 0f b6 4c 0c 20 48 8b 94 24 30 02 00 00 0f b6 04 02 33 c1 8b 4c 24 0c 48 8b 94 24 30 02 00 00 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}