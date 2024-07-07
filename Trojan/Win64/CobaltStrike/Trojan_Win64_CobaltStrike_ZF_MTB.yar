
rule Trojan_Win64_CobaltStrike_ZF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 90 01 01 41 8b ca 2b c8 41 2b cb 41 8d 04 08 48 98 42 8a 8c 30 90 01 04 43 32 8c 31 90 01 04 48 8b 85 90 01 04 41 88 0c 01 44 03 c7 4c 03 cf 44 3b 85 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}