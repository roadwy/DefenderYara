
rule Trojan_Win64_CobaltStrike_COS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.COS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e9 41 8b c9 41 ff c1 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 0b 2b c8 48 63 c1 48 03 c0 0f b6 84 c6 08 02 00 00 41 30 40 ff 49 83 ea 01 75 c8 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}