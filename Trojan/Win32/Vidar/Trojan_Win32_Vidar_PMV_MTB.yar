
rule Trojan_Win32_Vidar_PMV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 08 88 0a eb 27 8b 55 08 03 95 f4 fb ff ff 0f b6 02 8b 8d 14 f0 ff ff 33 84 8d f8 fb ff ff 8b 95 f0 fb ff ff 03 95 f4 fb ff ff 88 02 e9 d5 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}