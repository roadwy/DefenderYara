
rule Trojan_Win64_Tedy_FG_MTB{
	meta:
		description = "Trojan:Win64/Tedy.FG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 84 24 a8 00 00 00 0f b6 84 04 98 04 00 00 8b 8c 24 10 01 00 00 c1 e1 03 48 8b 94 24 a0 04 00 00 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 8c 24 a8 00 00 00 88 84 0c a0 67 00 00 eb 87 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}