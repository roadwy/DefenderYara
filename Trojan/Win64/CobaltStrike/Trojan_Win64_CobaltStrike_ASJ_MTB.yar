
rule Trojan_Win64_CobaltStrike_ASJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 54 24 38 99 41 f7 f8 48 63 d2 0f b6 04 16 41 32 04 09 41 88 04 0a 48 8b 35 6f 1b 00 00 0f b6 04 16 41 88 04 09 48 83 c1 01 39 0d 65 1b 00 00 77 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}