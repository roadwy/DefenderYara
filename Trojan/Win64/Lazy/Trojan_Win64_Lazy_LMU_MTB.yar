
rule Trojan_Win64_Lazy_LMU_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b 56 0a 8a 46 22 66 42 fe c0 55 66 89 56 24 88 46 23 } //20
		$a_03_1 = {8b 0e 25 ff ff 00 00 c1 e0 02 8b f8 66 8b 14 0f 8b ce 52 e8 ?? ?? ?? ?? 90 90 8b 06 66 8b 4c 07 02 51 8b ce } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}