
rule Trojan_Win32_Tinba_AHB_MTB{
	meta:
		description = "Trojan:Win32/Tinba.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 6c ff ff ff 8b 55 dc c1 f8 1f 8b c8 33 ca 8b 55 d8 33 c2 3b c1 0f } //3
		$a_01_1 = {89 85 38 fe ff ff 89 85 34 fe ff ff 89 85 30 fe ff ff 89 85 2c fe ff ff 89 85 28 fe ff ff 89 85 18 fe ff ff 89 85 08 fe ff ff ff 15 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}