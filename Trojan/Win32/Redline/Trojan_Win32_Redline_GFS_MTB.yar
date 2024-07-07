
rule Trojan_Win32_Redline_GFS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 88 90 01 04 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 e8 90 01 04 50 e8 90 01 04 59 28 1c 37 46 8b 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}