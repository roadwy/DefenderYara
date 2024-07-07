
rule Trojan_Win32_Emotet_DHL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 4d fc c1 e0 04 03 45 f8 33 c8 8d 04 3b 33 c8 8d 9b 90 01 04 8b 45 f4 2b f1 4a 75 90 01 01 8b 55 08 89 7a 04 5f 89 32 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}