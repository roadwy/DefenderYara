
rule Trojan_Win64_Oyster_CQ_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {4b 45 52 4e c7 45 ?? 45 4c 33 32 c7 45 ?? 2e 44 4c 4c } //2
		$a_03_1 = {4c 69 62 72 c7 45 ?? 61 72 79 41 } //2
		$a_01_2 = {47 65 74 50 } //2 GetP
		$a_03_3 = {72 6f 63 41 c7 45 ?? 64 64 72 65 66 c7 45 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=8
 
}