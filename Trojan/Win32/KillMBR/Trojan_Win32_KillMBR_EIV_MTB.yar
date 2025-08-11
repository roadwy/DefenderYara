
rule Trojan_Win32_KillMBR_EIV_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f6 24 80 88 84 0d ?? ?? ?? ?? 41 81 f9 80 a9 03 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}