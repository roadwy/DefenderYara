
rule TrojanProxy_Win32_Bunitu_RL_MTB{
	meta:
		description = "TrojanProxy:Win32/Bunitu.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 14 30 8b 45 f8 0f b6 08 03 ca 8b 55 f8 88 0a } //1
		$a_02_1 = {31 4d fc 8b 45 fc c7 45 fc ?? ?? ?? ?? 8b c8 b8 00 00 00 00 03 c1 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}