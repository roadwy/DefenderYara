
rule Trojan_Win32_Straba_RA_MTB{
	meta:
		description = "Trojan:Win32/Straba.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 89 ca 88 d3 ba 01 00 00 00 81 e9 b8 00 00 00 89 d6 89 85 90 01 01 fe ff ff 89 95 90 01 01 fe ff ff 88 9d 90 01 01 fe ff ff 89 8d 90 01 01 fe ff ff 89 b5 90 01 01 fe ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}