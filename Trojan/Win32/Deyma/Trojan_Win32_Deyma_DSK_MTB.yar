
rule Trojan_Win32_Deyma_DSK_MTB{
	meta:
		description = "Trojan:Win32/Deyma.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {6b c0 09 a3 ?? ?? ?? ?? 8b 85 2c fe ff ff 40 89 85 2c fe ff ff 8b 85 44 fe ff ff 33 05 ?? ?? ?? ?? 89 85 44 fe ff ff 8b 85 e4 fe ff ff b9 2c 01 00 00 ff e0 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}