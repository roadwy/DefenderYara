
rule Trojan_Win64_MoonWalk_A_MTB{
	meta:
		description = "Trojan:Win64/MoonWalk.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b6 47 15 33 d9 c1 e3 08 42 0f b6 0c 30 33 d9 41 33 1f 33 1d 4c 37 02 00 44 8b c3 41 89 5f 18 45 33 47 04 45 8b c8 45 89 47 1c 45 33 4f 08 45 8b d1 45 89 4f 20 45 33 57 0c 45 8b da 45 89 57 24 45 33 5f 10 41 8b c3 45 89 5f 28 41 33 47 14 8b d0 48 c1 e8 18 41 89 57 2c 42 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}