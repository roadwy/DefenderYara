
rule Trojan_Win32_Redline_HEV_MTB{
	meta:
		description = "Trojan:Win32/Redline.HEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 45 dc c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 f4 8b 45 ?? 31 45 ?? 8b 45 f4 31 45 ?? 8b 45 ?? 29 45 fc 68 ?? ?? ?? ?? 8d 45 f0 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}