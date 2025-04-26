
rule Trojan_Win32_CryptoBot_RDC_MTB{
	meta:
		description = "Trojan:Win32/CryptoBot.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 40 3d ff 00 00 00 7c f6 8b 45 08 32 ca 80 f1 0f 88 0c 06 b9 03 00 00 00 46 3b f7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}