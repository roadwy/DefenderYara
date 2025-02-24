
rule Trojan_Win64_FallenMiner_BSA_MTB{
	meta:
		description = "Trojan:Win64/FallenMiner.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 65 72 66 69 6e 61 6c 62 6f 74 } //12 minerfinalbot
		$a_01_1 = {3b 37 e0 ff 48 8d 0d f4 ef 01 00 48 89 4c 24 50 48 89 44 24 58 48 8d 05 78 cd 07 00 bb 0b 00 00 00 bf 01 } //8
		$a_03_2 = {48 8b 4c 24 30 48 85 c9 0f 85 36 ?? ?? ?? 48 8b 44 24 48 48 8b 5c 24 28 0f 1f 00 } //2
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*8+(#a_03_2  & 1)*2) >=22
 
}