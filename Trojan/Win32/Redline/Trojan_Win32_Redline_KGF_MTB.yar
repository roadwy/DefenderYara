
rule Trojan_Win32_Redline_KGF_MTB{
	meta:
		description = "Trojan:Win32/Redline.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c3 c1 e0 ?? 03 c7 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}