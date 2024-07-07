
rule Trojan_Win64_CobaltStrike_LKP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 03 b8 4f ec c4 4e 41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 8a 4c 18 18 42 30 0c 07 48 ff c7 45 3b cb 72 d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}