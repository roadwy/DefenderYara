
rule Trojan_Win32_Convagent_ADIA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ADIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 05 03 cb 89 55 ?? 8b 45 ?? 01 45 ?? 8b c3 c1 e0 04 03 45 ?? 33 45 ?? 33 c1 2b f8 89 7d ?? 8b 45 ?? 29 45 ?? 83 6d ?? 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}