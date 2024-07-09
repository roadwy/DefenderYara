
rule Trojan_Win32_Redline_GFM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3d 10 88 44 35 10 88 4c 3d 10 0f b6 44 35 10 03 c2 0f b6 c0 0f b6 44 05 10 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}