
rule Trojan_Win32_Redline_YUB_MTB{
	meta:
		description = "Trojan:Win32/Redline.YUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 4c 24 10 03 c6 0f b6 c0 8a 44 04 90 01 01 30 04 29 45 3b ac 24 20 02 00 00 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}