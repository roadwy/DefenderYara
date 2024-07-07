
rule Trojan_Win64_CobaltStrike_JI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b 04 03 48 83 c3 90 01 01 44 0f af 05 90 01 04 8b 05 90 01 04 ff c8 33 c8 48 8b 05 90 01 04 89 0d 90 01 04 49 63 c9 41 8b d0 c1 ea 90 01 01 88 14 01 8b 0d 90 01 04 8b 05 90 01 04 ff c1 01 05 90 01 04 8b 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}