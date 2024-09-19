
rule Trojan_Win64_CobaltStrike_PR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 f8 60 4d 8d 40 01 48 0f 44 c3 41 ff c2 0f b6 4c 04 30 48 ff c0 41 30 48 ff 49 63 ca 48 81 f9 [0-04] 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}