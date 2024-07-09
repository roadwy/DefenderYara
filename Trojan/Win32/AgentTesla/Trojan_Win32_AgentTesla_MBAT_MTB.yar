
rule Trojan_Win32_AgentTesla_MBAT_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.MBAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bf ab aa aa aa 66 2e 0f 1f 84 ?? ?? ?? ?? 00 0f 1f 40 00 89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 84 01 ?? ?? ?? ?? 30 44 0e 01 83 c1 02 39 cb 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}