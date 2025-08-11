
rule Trojan_Win32_KillMBR_EAN_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be d2 0f af d1 88 94 05 ?? ?? ?? ?? 40 3d 00 53 07 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}