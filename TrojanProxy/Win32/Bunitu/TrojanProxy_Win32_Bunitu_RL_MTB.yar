
rule TrojanProxy_Win32_Bunitu_RL_MTB{
	meta:
		description = "TrojanProxy:Win32/Bunitu.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 14 30 8b 45 f8 0f b6 08 03 ca 8b 55 f8 88 0a } //01 00 
		$a_02_1 = {31 4d fc 8b 45 fc c7 45 fc 90 01 04 8b c8 b8 00 00 00 00 03 c1 89 45 fc a1 90 01 04 8b 4d fc 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}