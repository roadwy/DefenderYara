
rule Trojan_Win64_CobaltStrike_JID_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 01 c1 8b 15 13 a5 06 00 8b 05 01 a5 06 00 0f af c2 29 c1 8b 15 fe a4 06 00 8b 05 90 01 04 0f af c2 29 c1 89 c8 48 63 d0 48 8d 05 90 01 04 0f b6 04 02 44 31 c8 41 88 00 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 e8 48 39 c2 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}