
rule Trojan_Win32_Qukart_AQK_MTB{
	meta:
		description = "Trojan:Win32/Qukart.AQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d8 01 d8 89 c3 31 d8 89 c3 29 d8 89 c3 81 c3 46 66 00 00 89 d8 29 d8 89 c3 81 c3 8f 0c 00 00 b8 92 0d 00 00 f7 e3 89 85 8c fe ff ff 89 c3 81 eb 49 51 00 00 81 eb 90 39 00 00 81 c3 db 11 00 00 89 d8 01 d8 89 c3 31 d8 89 c3 81 eb 5e 14 00 00 89 d8 f7 e3 89 85 88 fe ff ff 89 c3 81 c3 be 25 00 00 6a 01 8d 85 01 ff ff ff 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}