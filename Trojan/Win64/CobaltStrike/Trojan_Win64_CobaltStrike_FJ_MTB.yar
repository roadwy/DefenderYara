
rule Trojan_Win64_CobaltStrike_FJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 48 8b 05 90 01 04 ff 40 90 01 01 8b 4b 90 01 01 8b 93 90 01 04 8b 43 90 01 01 33 05 90 01 04 ff c8 09 83 90 01 04 8d 82 90 01 04 33 53 90 01 01 03 c1 31 43 90 01 01 81 ea 90 01 04 2b 4b 90 01 01 ff c1 89 4b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}