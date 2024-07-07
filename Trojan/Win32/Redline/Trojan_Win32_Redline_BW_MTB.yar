
rule Trojan_Win32_Redline_BW_MTB{
	meta:
		description = "Trojan:Win32/Redline.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c 10 01 00 00 88 84 34 10 01 00 00 88 8c 3c 10 01 00 00 0f b6 84 34 10 01 00 00 03 c2 0f b6 c0 0f b6 84 04 10 01 00 00 30 83 90 02 04 43 81 fb 90 02 04 7c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}