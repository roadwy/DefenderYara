
rule Trojan_Win32_Qukart_AQU_MTB{
	meta:
		description = "Trojan:Win32/Qukart.AQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c3 29 d8 89 c3 29 d8 89 c3 29 d8 89 c3 68 04 01 00 00 8d 85 fc fe ff ff 50 e8 ?? ?? ?? ?? 89 d8 f7 e3 89 85 d8 fe ff ff 89 c3 81 f3 10 09 00 00 89 d8 31 d8 89 c3 8d 85 ec fe ff ff 50 8d 85 fc fe ff ff 50 68 a0 30 00 10 8d 85 fc fe ff ff 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}