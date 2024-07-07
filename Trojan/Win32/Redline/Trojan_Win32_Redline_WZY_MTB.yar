
rule Trojan_Win32_Redline_WZY_MTB{
	meta:
		description = "Trojan:Win32/Redline.WZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 45 90 01 01 03 fe 33 f8 31 7d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 68 90 01 04 8d 45 90 01 01 50 e8 90 01 04 ff 4d 90 01 01 8b 45 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}