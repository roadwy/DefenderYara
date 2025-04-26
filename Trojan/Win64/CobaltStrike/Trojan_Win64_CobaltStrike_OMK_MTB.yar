
rule Trojan_Win64_CobaltStrike_OMK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c9 2b c1 48 8d 0d 5e 21 00 00 42 0f b6 04 20 32 04 3e 0f b6 d0 88 17 e8 d4 fd ff ff ff c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}