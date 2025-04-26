
rule Trojan_Win64_CobaltStrike_PABP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 6b d0 64 0f 57 c0 f2 48 0f 2a c7 66 0f 2f c6 41 0f 97 c0 49 8b ce 45 84 c0 48 0f 44 cf 48 03 ca 49 8b c7 48 f7 e9 48 c1 fa 1a 48 8b c2 48 c1 e8 3f 48 03 d0 48 89 54 24 28 48 69 c2 00 ca 9a 3b 48 2b c8 89 4c 24 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}