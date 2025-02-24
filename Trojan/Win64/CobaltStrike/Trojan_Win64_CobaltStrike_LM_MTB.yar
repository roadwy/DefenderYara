
rule Trojan_Win64_CobaltStrike_LM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c2 99 41 23 d7 03 c2 41 23 c7 2b c2 8a 54 04 30 41 30 10 49 ff c0 49 83 e9 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}