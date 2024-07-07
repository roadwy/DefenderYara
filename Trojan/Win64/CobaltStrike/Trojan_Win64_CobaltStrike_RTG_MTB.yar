
rule Trojan_Win64_CobaltStrike_RTG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 f7 e1 48 c1 ea 04 48 6b c2 11 49 8b d1 48 2b d0 42 8a 04 02 42 30 04 09 49 ff c1 4d 3b ca 76 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}