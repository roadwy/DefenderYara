
rule Trojan_Win32_Redline_SMG_MTB{
	meta:
		description = "Trojan:Win32/Redline.SMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 89 1d ?? ?? ?? ?? 31 45 ?? 8b 45 ?? 29 45 ?? 81 45 ?? ?? ?? ?? ?? ff 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}