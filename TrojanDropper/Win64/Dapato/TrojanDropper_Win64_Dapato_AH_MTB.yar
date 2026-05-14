
rule TrojanDropper_Win64_Dapato_AH_MTB{
	meta:
		description = "TrojanDropper:Win64/Dapato.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 72 65 72 75 6e 45 6c 65 76 61 74 65 64 } //40 main.rerunElevated
		$a_01_1 = {72 75 6e 20 70 61 79 6c 6f 61 64 3a } //30 run payload:
		$a_03_2 = {48 89 5c 24 38 48 89 44 24 50 48 8d ?? ?? ?? ?? 00 bb 18 00 00 00 31 c9 31 ff 48 89 fe 0f 1f 44 00 00 } //20
	condition:
		((#a_01_0  & 1)*40+(#a_01_1  & 1)*30+(#a_03_2  & 1)*20) >=90
 
}