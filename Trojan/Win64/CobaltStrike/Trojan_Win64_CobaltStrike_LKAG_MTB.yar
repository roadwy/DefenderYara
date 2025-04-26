
rule Trojan_Win64_CobaltStrike_LKAG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f0 21 f8 31 f7 09 c7 89 7c 24 44 44 89 c0 e9 9f fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}