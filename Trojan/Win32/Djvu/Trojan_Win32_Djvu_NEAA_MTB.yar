
rule Trojan_Win32_Djvu_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Djvu.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa d3 ea 89 55 f8 8b 45 c8 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8d 45 e0 e8 ?? ?? ?? ?? ff 4d dc 0f 85 d4 fe ff ff 8b 4d f4 8b 45 08 5f 89 08 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}