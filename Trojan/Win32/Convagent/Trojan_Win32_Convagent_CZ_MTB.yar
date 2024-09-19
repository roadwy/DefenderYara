
rule Trojan_Win32_Convagent_CZ_MTB{
	meta:
		description = "Trojan:Win32/Convagent.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb c1 e9 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 ?? 03 74 24 ?? 8d 14 1f 33 f2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}