
rule Trojan_Win32_Redline_PCX_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e3 89 c8 c1 ea ?? 6b d2 ?? 29 d0 0f b6 80 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 83 c1 01 83 f0 e5 88 81 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}