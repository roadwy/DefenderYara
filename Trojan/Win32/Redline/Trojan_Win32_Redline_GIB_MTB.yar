
rule Trojan_Win32_Redline_GIB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 1e 83 e3 03 8a 8b 90 01 04 32 ca 0f b6 da 8d 04 19 8b 75 c0 8b 4d bc 88 04 31 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}