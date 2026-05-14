
rule Trojan_Win64_CutFailMiner_YBE_MTB{
	meta:
		description = "Trojan:Win64/CutFailMiner.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 66 89 41 04 0f b6 c2 32 41 06 34 7a 0f b6 c0 66 89 41 06 0f b6 c2 32 41 ?? 34 b7 0f b6 c0 66 89 } //2
		$a_01_1 = {40 32 f9 80 c1 ?? 40 0f b6 c7 66 89 44 54 42 32 4c 24 40 32 4c 54 44 0f b6 c1 66 89 44 54 } //2
		$a_01_2 = {49 64 6c 6c 45 6e 74 72 79 } //1 IdllEntry
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}