
rule Trojan_Win32_Redline_ZMJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? ff 75 ?? c1 e0 04 03 c7 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}