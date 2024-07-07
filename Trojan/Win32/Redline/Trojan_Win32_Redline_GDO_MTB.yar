
rule Trojan_Win32_Redline_GDO_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 b9 90 01 04 8a 80 90 01 04 32 86 90 01 04 88 85 90 01 04 e8 90 01 04 8b f8 8b 0f 8b 49 04 8b 4c 39 30 8b 49 04 89 8d 90 01 04 8b 11 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}