
rule Trojan_Win32_Convagent_RZ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 03 4d ?? c1 ?? 04 03 5d ?? 33 d9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}