
rule Trojan_Win32_Remcos_PR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5a b9 e0 d4 00 00 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 83 e9 ?? 7d ?? ff ?? e2 ?? 99 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}