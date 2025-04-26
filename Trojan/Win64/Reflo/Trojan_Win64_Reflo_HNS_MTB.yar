
rule Trojan_Win64_Reflo_HNS_MTB{
	meta:
		description = "Trojan:Win64/Reflo.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 17 41 89 c2 41 83 e2 1f 45 32 0c 12 44 88 0c 07 48 ff c0 48 39 c6 74 ac 44 0f b6 0c 07 45 84 c0 74 df } //2
		$a_01_1 = {48 89 78 18 48 c7 40 28 00 00 06 00 48 c7 40 30 08 00 00 00 48 8b 4c 24 58 } //2
		$a_01_2 = {42 00 51 00 38 00 6a 00 67 00 67 00 5a 00 63 00 69 00 38 00 64 00 63 00 69 00 67 00 64 00 61 00 48 00 5a 00 69 00 51 00 48 00 5a 00 67 00 6b 00 } //2 BQ8jggZci8dcigdaHZiQHZgk
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}