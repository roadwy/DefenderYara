
rule Trojan_Win32_Redline_GDP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 98 90 01 04 32 9e 90 01 04 ba 90 01 04 e8 90 01 04 50 e8 90 01 04 83 c4 04 0f b6 86 90 01 04 8d 0c 03 88 8e 90 01 04 2a c8 88 8e 90 01 04 46 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}