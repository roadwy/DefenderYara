
rule Trojan_Win32_Zbot_AV_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 55 b0 0f b7 45 a4 0f af d0 8b 45 b8 0f b6 0c 10 83 f1 44 8b 45 b4 01 c8 89 45 b4 0f b7 55 a4 c1 e2 18 88 55 a0 8a 55 ac 84 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}