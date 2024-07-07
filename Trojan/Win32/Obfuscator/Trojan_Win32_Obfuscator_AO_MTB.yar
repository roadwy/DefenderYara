
rule Trojan_Win32_Obfuscator_AO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.AO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 85 f7 fe ff ff 8a 84 0d f8 fe ff ff 88 84 35 f8 fe ff ff 88 94 0d f8 fe ff ff 0f b6 84 35 f8 fe ff ff 0f b6 ca 03 c8 0f b6 c1 8a 84 05 f8 fe ff ff 30 04 3b 43 8a 85 f7 fe ff ff 3b 5d 0c 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}