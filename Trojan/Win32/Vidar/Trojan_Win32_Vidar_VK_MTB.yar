
rule Trojan_Win32_Vidar_VK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 32 c1 8b 8d 80 e4 ff ff 88 04 31 ff b5 74 e4 ff ff ff 85 84 e4 ff ff 46 e8 90 01 04 59 39 85 84 e4 ff ff 0f 8c 62 ff ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}