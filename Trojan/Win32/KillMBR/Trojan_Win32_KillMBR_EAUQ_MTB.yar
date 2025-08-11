
rule Trojan_Win32_KillMBR_EAUQ_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EAUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a c3 c0 e0 05 0a d0 88 94 1d ?? ?? ?? ?? 43 81 fb 80 a9 03 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}