
rule Trojan_Win64_BadJoke_KK_MTB{
	meta:
		description = "Trojan:Win64/BadJoke.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c1 83 e0 03 42 0f b6 04 30 30 04 0b 48 ff c1 8b 44 24 48 48 3b c8 72 } //20
		$a_01_1 = {66 31 18 48 83 c0 02 48 3b c2 75 f4 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}