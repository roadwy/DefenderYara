
rule Trojan_Win32_Redline_GKH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 94 05 ?? ?? ?? ?? 01 c2 31 c2 80 c2 ?? 80 f2 ?? 0f b6 d2 01 c2 31 c2 80 f2 ?? 00 ca 30 c2 88 94 05 ?? ?? ?? ?? 83 c0 ?? 80 c1 ?? 83 f8 ?? 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}