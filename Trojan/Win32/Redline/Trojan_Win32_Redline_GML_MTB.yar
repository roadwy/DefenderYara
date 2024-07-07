
rule Trojan_Win32_Redline_GML_MTB{
	meta:
		description = "Trojan:Win32/Redline.GML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b ca 88 8d 90 01 04 0f b6 85 90 01 04 f7 d0 88 85 90 01 04 0f b6 8d 90 01 04 03 8d 90 01 04 88 8d 90 01 04 0f b6 95 90 01 04 f7 d2 88 95 90 01 04 0f b6 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}