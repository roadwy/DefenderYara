
rule Trojan_Win32_RedLineStealer_RPQ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 28 45 d0 0f 29 85 50 fe ff ff 8b 95 78 ff ff ff 0f 10 02 0f 29 85 60 fe ff ff 0f 28 85 60 fe ff ff 66 0f ef 85 50 fe ff ff 0f 29 85 40 fe ff ff 0f 28 85 40 fe ff ff 8b 85 78 ff ff ff 0f 11 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}