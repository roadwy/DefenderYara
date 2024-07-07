
rule Trojan_Win64_CobaltStrike_YAN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c1 83 c0 ff 48 8b 8c 24 90 01 04 8b 49 50 33 c8 8b c1 48 8b 8c 24 f0 00 00 00 89 41 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}