
rule Trojan_Win64_Donut_SX_MTB{
	meta:
		description = "Trojan:Win64/Donut.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8d 54 24 78 48 83 7d 90 90 0f 48 0f 47 54 24 78 4c 89 6c 24 20 4c 8d 4c 24 34 44 8b 45 88 49 8b 4c 24 08 ff 15 ?? ?? ?? ?? 48 8b 55 90 90 48 83 fa 0f 76 } //20
		$a_03_1 = {4d 8b c6 4c 2b c7 49 ff c0 48 2b cf 49 3b c8 4c 0f 42 c1 48 8d 54 24 ?? 48 83 7c 24 ?? 0f 48 0f 47 54 24 ?? 48 03 d7 48 8d 4c 24 } //5
		$a_01_2 = {5b 59 59 53 68 61 72 70 5d } //15 [YYSharp]
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*5+(#a_01_2  & 1)*15) >=40
 
}