
rule Trojan_Win32_AgentTesla_Z_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c6 f7 f1 8b 45 ?? 8a 0c 02 8d 14 ?? 8b 45 ?? 46 8a 04 10 32 c1 88 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}