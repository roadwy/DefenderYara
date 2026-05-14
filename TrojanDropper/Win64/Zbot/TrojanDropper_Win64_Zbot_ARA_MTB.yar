
rule TrojanDropper_Win64_Zbot_ARA_MTB{
	meta:
		description = "TrojanDropper:Win64/Zbot.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 1c 07 00 00 48 98 0f b6 84 05 c8 04 00 00 83 f0 7f 89 c2 8b 85 1c 07 00 00 48 98 88 94 05 c8 04 00 00 83 85 1c 07 00 00 01 83 bd 1c 07 00 00 07 7e cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}