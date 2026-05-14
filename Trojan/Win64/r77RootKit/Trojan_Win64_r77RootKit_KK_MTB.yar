
rule Trojan_Win64_r77RootKit_KK_MTB{
	meta:
		description = "Trojan:Win64/r77RootKit.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 c0 66 45 03 c3 48 8d 14 80 41 8b 74 d2 14 41 8b 7c d2 0c 49 03 f6 41 8b 4c d2 10 48 03 fd f3 a4 66 44 3b 43 06 72 d6 } //20
		$a_03_1 = {0f b7 c3 41 c1 c9 ?? 42 0f be 0c 18 80 f9 ?? 8b d1 8d 41 ?? 0f 4d d0 66 03 dd 44 03 ca 66 41 3b 58 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}