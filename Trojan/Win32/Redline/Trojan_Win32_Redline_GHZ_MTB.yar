
rule Trojan_Win32_Redline_GHZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 55 c0 0f b6 45 c0 0f b7 4d bc 33 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 33 c8 33 d2 89 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 9c 8b 4d a0 05 ?? ?? ?? ?? 81 d1 ?? ?? ?? ?? 89 45 b0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}