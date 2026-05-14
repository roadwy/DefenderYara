
rule Trojan_Win64_BadJoke_MK_MTB{
	meta:
		description = "Trojan:Win64/BadJoke.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 85 04 01 00 00 0f b6 8d 24 01 00 00 c1 e1 08 0b c1 0f b6 8d 44 01 00 00 c1 e1 10 0b c1 44 8b c0 ba 05 } //20
		$a_01_1 = {8b 85 64 01 00 00 ff c0 89 85 64 01 00 00 8b 85 64 01 00 00 8b 8d 08 01 00 00 2b c8 8b c1 b9 08 00 00 00 48 6b c9 00 89 84 0d 38 01 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}