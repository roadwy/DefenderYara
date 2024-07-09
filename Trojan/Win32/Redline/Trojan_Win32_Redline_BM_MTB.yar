
rule Trojan_Win32_Redline_BM_MTB{
	meta:
		description = "Trojan:Win32/Redline.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 83 c2 01 89 55 f0 8b 45 f0 3b 05 ?? ?? ?? ?? 73 22 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 f0 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d f0 88 01 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}