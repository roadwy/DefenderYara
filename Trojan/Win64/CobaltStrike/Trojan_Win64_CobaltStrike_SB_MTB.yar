
rule Trojan_Win64_CobaltStrike_SB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 09 49 30 44 33 81 90 01 04 41 2b c0 01 41 90 01 01 48 8b 81 90 01 04 0f b6 51 90 01 01 45 0f b6 04 03 49 83 c3 90 01 01 48 8b 81 90 01 04 44 0f af c2 48 63 51 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}