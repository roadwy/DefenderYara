
rule Trojan_Win32_Redline_GFU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 30 8b c6 83 e0 03 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d cc 88 04 31 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}