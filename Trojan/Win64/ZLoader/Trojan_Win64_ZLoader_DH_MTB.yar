
rule Trojan_Win64_ZLoader_DH_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {b4 bd 0b 11 1d 63 0b 0c 6d 01 7d e9 5b 10 d9 39 58 20 15 5d 61 56 a0 b8 62 2b 21 56 03 0f 1d 47 8c 39 74 34 fd c1 3d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}