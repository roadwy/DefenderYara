
rule Trojan_Win32_Redline_GBK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 0d ?? ?? ?? ?? 73 21 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 fc 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 55 fc 88 0a eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}