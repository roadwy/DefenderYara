
rule Trojan_Win64_CobaltStrike_TQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 14 90 01 01 8d 48 90 01 01 80 f9 90 01 01 77 90 01 01 2c 90 01 01 88 44 14 90 01 01 48 ff c2 48 3b d6 90 00 } //1
		$a_03_1 = {8b c8 c1 e9 90 01 01 33 c8 69 c9 90 01 04 33 e9 49 83 e8 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}