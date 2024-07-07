
rule Trojan_Win32_Qbot_RL_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 8a 98 90 01 04 88 90 01 05 88 99 90 01 04 0f b6 90 01 05 a3 90 01 04 0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a 90 01 04 30 0c 37 83 6c 24 90 01 01 01 8b 74 24 90 01 01 85 f6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}