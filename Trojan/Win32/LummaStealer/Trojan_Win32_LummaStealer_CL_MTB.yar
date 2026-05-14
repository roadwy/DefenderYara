
rule Trojan_Win32_LummaStealer_CL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 c8 0f b6 04 16 88 0d ?? ?? ?? ?? 42 8a 0d ?? ?? ?? ?? 32 c8 88 0d ?? ?? ?? ?? 80 3c 16 00 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}