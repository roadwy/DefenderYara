
rule Trojan_Win32_Redline_GFJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1d ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 05 ?? ?? ?? ?? 32 87 ?? ?? ?? ?? 88 87 ?? ?? ?? ?? 47 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}