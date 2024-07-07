
rule Trojan_Win32_LokiBot_UY_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.UY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 44 75 1c 26 34 c7 45 98 f3 3c 60 32 c7 85 40 fe ff ff 37 2f cb 38 c7 45 a0 89 59 48 52 c7 85 a0 fe ff ff ca e0 34 6f c7 85 e8 fe ff ff 20 13 17 00 c7 85 48 fe ff ff 3b 9d af 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}