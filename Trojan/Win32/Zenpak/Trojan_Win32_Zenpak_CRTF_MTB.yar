
rule Trojan_Win32_Zenpak_CRTF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CRTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 42 31 2d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 00 af } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}