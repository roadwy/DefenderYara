
rule Trojan_Win32_Redline_GFY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 34 90 01 04 03 c2 0f b6 c0 8a 84 04 90 01 04 30 83 90 01 04 43 81 fb 90 01 04 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}