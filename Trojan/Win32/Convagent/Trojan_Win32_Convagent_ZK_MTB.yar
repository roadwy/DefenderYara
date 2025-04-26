
rule Trojan_Win32_Convagent_ZK_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 03 45 d0 89 45 f0 33 45 e4 31 45 fc 8b 45 fc 29 45 f8 81 c7 ?? ?? ?? ?? 89 7d ec 4e 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}