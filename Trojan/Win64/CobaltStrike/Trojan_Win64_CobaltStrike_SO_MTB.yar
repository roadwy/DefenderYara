
rule Trojan_Win64_CobaltStrike_SO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 01 41 90 01 02 41 90 01 03 49 90 01 03 49 90 01 06 c1 ea 90 01 01 88 14 01 41 90 01 03 41 90 01 06 41 90 01 06 41 90 01 06 35 90 01 04 41 90 01 06 41 90 01 03 41 90 01 03 41 90 01 03 81 c1 90 01 04 03 d1 0f af c2 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}