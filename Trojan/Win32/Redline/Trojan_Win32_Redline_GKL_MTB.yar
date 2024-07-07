
rule Trojan_Win32_Redline_GKL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 1c 90 01 04 88 84 3c 90 01 04 8a 44 24 90 01 01 88 84 1c 90 01 04 0f b6 84 3c 90 01 04 03 44 24 90 01 01 0f b6 c0 0f b6 84 04 90 01 04 30 86 90 01 04 46 81 fe 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}