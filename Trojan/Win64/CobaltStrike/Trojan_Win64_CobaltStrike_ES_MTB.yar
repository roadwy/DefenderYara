
rule Trojan_Win64_CobaltStrike_ES_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 89 c0 49 f7 e1 4c 89 c1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 04 48 8d 04 92 48 8d 04 82 4c 89 c6 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 01 3d 20 00 42 32 04 02 48 8b 94 24 88 06 00 00 42 88 04 02 49 83 c0 01 4c 39 84 24 80 06 00 00 77 af ff 94 24 88 06 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}