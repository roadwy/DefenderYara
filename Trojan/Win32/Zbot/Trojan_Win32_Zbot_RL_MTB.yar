
rule Trojan_Win32_Zbot_RL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 03 33 c6 03 02 2b 02 89 01 03 15 90 01 04 83 c7 01 8b c7 ff 75 18 8f 45 e8 2b 45 e8 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}