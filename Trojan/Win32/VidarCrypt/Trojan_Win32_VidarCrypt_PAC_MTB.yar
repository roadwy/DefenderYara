
rule Trojan_Win32_VidarCrypt_PAC_MTB{
	meta:
		description = "Trojan:Win32/VidarCrypt.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 33 c8 8d 04 3b 33 c8 89 4d fc 8b 45 fc 90 02 0f 2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e8 8d 14 33 33 ca 33 c8 2b f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}