
rule Trojan_Win64_CobaltStrike_LKJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ea 08 88 14 01 ff 43 74 8b 83 88 00 00 00 48 63 53 74 48 8b 8b b0 00 00 00 01 83 fc 00 00 00 44 88 04 0a b9 75 cd 19 00 2b 8b a0 00 00 00 ff 43 74 89 4b 18 49 81 f9 10 14 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}