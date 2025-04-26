
rule Trojan_Win32_Raccoon_MKY_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 06 83 c4 08 0f b6 0f 03 c8 0f b6 c1 8b 8d f8 fe ff ff 8a 84 05 fc fe ff ff 30 81 ?? ?? ?? ?? 41 89 8d f8 fe ff ff 81 f9 00 ca 00 00 8b 8d f4 fe ff ff 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}