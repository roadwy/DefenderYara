
rule Trojan_Win32_KillMBR_EANI_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EANI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 04 0a 95 ?? ?? ?? ?? 32 da 8b 95 ?? ?? ?? ?? 88 9c 15 ?? ?? ?? ?? 42 89 95 ?? ?? ?? ?? 81 fa 10 09 05 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}