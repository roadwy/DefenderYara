
rule Trojan_Win32_Redline_GHO_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 1d 10 88 44 3d 10 88 4c 1d 10 0f b6 44 3d 10 03 c2 0f b6 c0 0f b6 44 05 10 32 86 90 01 04 88 86 90 01 04 46 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}