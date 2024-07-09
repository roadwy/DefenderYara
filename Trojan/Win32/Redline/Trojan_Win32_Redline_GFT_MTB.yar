
rule Trojan_Win32_Redline_GFT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0f 0f b6 06 03 c8 0f b6 c1 8a 84 05 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}