
rule Trojan_Win64_Pikabot_AK_MTB{
	meta:
		description = "Trojan:Win64/Pikabot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 f0 4c 89 fa 48 89 f9 48 83 c7 02 e8 ?? ?? ?? ?? 48 89 d8 31 d2 48 83 c3 01 48 f7 f5 41 0f b6 44 15 00 30 06 48 83 c6 01 49 39 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}