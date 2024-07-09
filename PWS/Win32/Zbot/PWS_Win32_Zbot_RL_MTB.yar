
rule PWS_Win32_Zbot_RL_MTB{
	meta:
		description = "PWS:Win32/Zbot.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 ec 0f b6 0c 10 8b 55 f4 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d f4 88 81 ?? ?? ?? ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}