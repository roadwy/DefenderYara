
rule Trojan_Win32_Redline_GCH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 8b 45 ?? 8a 88 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 8b 45 ?? 0f b6 88 ?? ?? ?? ?? 03 ca 8b 55 d8 88 8a ?? ?? ?? ?? 8a 45 ?? 88 45 ?? 0f b6 4d ?? 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 2b c1 8b 4d d8 88 81 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}