
rule Trojan_Win32_AgentTesla_GS_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d4 89 45 c0 90 05 10 01 90 8b 45 d0 01 45 c0 90 05 10 01 90 8b 45 ec 89 45 c4 8b 45 c4 8a 80 88 f2 48 00 88 45 fb 90 05 10 01 90 c6 45 df 25 8a 45 fb 32 45 df 8b 55 c0 88 02 90 05 10 01 90 ff 45 ec 81 7d ec 32 5d 00 00 75 aa } //1
		$a_02_1 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 05 10 01 90 8b 7d fc ff 75 f8 01 3c 24 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}