
rule Trojan_Win64_Dridex_GME_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 44 24 56 8a 4c 24 07 80 f1 ff 48 8b 54 24 58 88 4c 24 71 66 05 4a 92 48 81 f2 ?? ?? ?? ?? 4c 8b 44 24 28 49 01 d0 66 c7 44 24 72 93 41 4c 89 44 24 20 66 3b 44 24 46 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}