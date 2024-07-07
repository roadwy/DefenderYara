
rule Trojan_Win64_CobaltStrike_CXO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c9 03 d1 45 8b 04 01 41 33 d2 8b 43 2c 49 83 c1 90 01 01 89 53 90 01 01 83 f0 90 01 01 01 83 90 01 04 48 63 8b 90 01 04 44 0f af 43 90 01 01 48 8b 83 90 01 04 41 8b d0 c1 ea 90 01 01 88 14 01 ff 83 90 01 04 48 63 8b 90 01 04 48 8b 83 90 01 04 44 88 04 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}