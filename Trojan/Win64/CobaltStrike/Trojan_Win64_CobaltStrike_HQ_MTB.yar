
rule Trojan_Win64_CobaltStrike_HQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 49 01 41 f7 e8 41 8b c8 41 ff c0 d1 fa 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 63 c1 0f b6 4c 05 90 01 01 41 30 49 90 01 01 41 81 f8 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}