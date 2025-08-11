
rule Trojan_Win32_KillMBR_EYB_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a d0 88 94 1d ?? ?? ?? ?? 43 81 fb 80 a9 03 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}