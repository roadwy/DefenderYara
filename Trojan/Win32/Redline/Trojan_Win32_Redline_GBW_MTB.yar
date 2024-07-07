
rule Trojan_Win32_Redline_GBW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 2e 0f b6 89 90 01 04 30 88 90 01 04 8d 48 01 83 e1 2f 0f b6 89 90 01 04 30 88 90 01 04 83 c0 02 3d 90 01 04 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}