
rule Trojan_Win64_DllHijack_ADH_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.ADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {d3 2a 45 3c 13 ab 65 ad 1b e3 0d a4 c3 ab ed 34 0b 43 35 2d 33 3a ad } //5
		$a_03_1 = {66 44 1b d7 4c 33 c7 45 8d 80 ?? ?? ?? ?? 45 0f b6 da 4a 8d 3c d5 ?? ?? ?? ?? 49 d1 f0 66 41 81 ea 87 39 66 41 c1 fa 24 41 0f 97 c2 } //3
		$a_03_2 = {51 41 53 f6 d3 8b 9c 1c ?? ?? ?? ?? 41 81 e0 11 b0 1b 67 81 f3 9a 5f 94 82 48 c1 cf a8 d1 c3 42 8d 9c 03 ?? ?? ?? ?? 41 87 fa 44 32 c7 41 50 f7 d3 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}