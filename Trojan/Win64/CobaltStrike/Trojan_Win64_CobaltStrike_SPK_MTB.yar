
rule Trojan_Win64_CobaltStrike_SPK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 ab aa aa 2a 4d 8d 40 01 41 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c2 41 ff c2 8d 0c 52 c1 e1 02 2b c1 48 63 c8 0f b6 04 31 41 30 40 ff 49 83 eb 01 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}