
rule Trojan_Win64_CobaltStrike_HNH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 50 30 00 10 8b d8 8d 6d 28 8b 44 24 10 40 6a 00 89 44 24 14 59 66 3b 46 06 72 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}