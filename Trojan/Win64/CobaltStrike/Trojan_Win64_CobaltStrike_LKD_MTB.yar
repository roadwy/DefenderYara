
rule Trojan_Win64_CobaltStrike_LKD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 6b d2 42 2b c2 48 63 c8 48 90 01 04 42 90 01 06 00 00 41 90 01 04 41 90 01 04 3b 6c 24 60 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}