
rule TrojanDropper_Win64_Convagent_AHB_MTB{
	meta:
		description = "TrojanDropper:Win64/Convagent.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 85 e8 fd ff ff 48 c1 e0 ?? 48 8d 8d f8 fd ff ff 48 01 c1 0f b7 01 83 f8 ?? 0f } //30
		$a_01_1 = {57 69 6e 4d 61 69 6e 50 61 79 6c 6f 61 64 } //20 WinMainPayload
		$a_01_2 = {6f 73 64 6d 6e 75 73 5f 75 6e 69 5f 73 6f 75 72 63 65 2e 63 } //10 osdmnus_uni_source.c
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}