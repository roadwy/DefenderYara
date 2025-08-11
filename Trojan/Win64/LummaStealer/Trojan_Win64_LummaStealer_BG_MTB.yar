
rule Trojan_Win64_LummaStealer_BG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 24 89 44 24 60 8a c2 32 44 24 34 0f b6 c0 66 a3 ?? ?? ?? 00 8b 44 24 70 03 c3 a3 ?? ?? ?? 00 3b 44 24 4c 75 } //3
		$a_01_1 = {32 c1 8b 4c 24 40 32 44 24 11 30 04 11 42 8b 44 24 24 40 89 54 24 14 89 44 24 24 81 fa } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}