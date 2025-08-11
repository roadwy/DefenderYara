
rule Trojan_Win64_Midie_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Midie.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {f1 33 cd 31 aa ?? ?? ?? ?? 5a 89 95 ?? ?? ?? ?? 34 04 1e 58 03 15 ?? ?? ?? ?? c9 b7 49 b4 b4 41 e1 f4 } //10
		$a_01_1 = {ec 50 1e 32 62 a7 a4 63 80 } //5
		$a_03_2 = {18 31 10 42 ?? 54 02 20 35 ?? ?? ?? ?? 1a cb } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5) >=10
 
}