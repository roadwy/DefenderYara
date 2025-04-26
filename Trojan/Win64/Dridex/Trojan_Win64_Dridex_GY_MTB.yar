
rule Trojan_Win64_Dridex_GY_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {42 8a 1c 1a 44 28 cb 48 2b 4c 24 ?? 4c 8b 44 24 ?? 43 88 1c 18 8b 44 24 ?? 0f af c0 89 44 24 ?? 49 01 cb 48 8b 4c 24 ?? 48 c7 44 24 ?? ?? ?? ?? ?? 41 b1 ?? 8a 44 24 ?? 41 f6 e1 88 44 24 ?? 4c 89 5c 24 ?? b0 6f 44 8a 4c 24 ?? 88 44 24 ?? 44 88 c8 8a 5c 24 ?? f6 e3 88 44 24 ?? 49 39 cb 0f 85 } //10
		$a_80_1 = {46 47 54 37 74 2e 70 64 62 } //FGT7t.pdb  1
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}