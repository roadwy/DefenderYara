
rule Trojan_Win64_Bobik_AHB_MTB{
	meta:
		description = "Trojan:Win64/Bobik.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 48 59 00 00 00 c7 44 24 48 5e 00 00 00 c7 44 24 48 63 00 00 00 c7 44 24 48 68 00 00 00 } //30
		$a_03_1 = {89 f1 48 69 c9 ?? ?? ?? ?? 48 c1 e9 ?? 48 01 c1 48 39 c1 0f 93 c0 84 c0 74 } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}