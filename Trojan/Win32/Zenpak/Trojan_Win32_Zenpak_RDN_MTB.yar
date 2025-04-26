
rule Trojan_Win32_Zenpak_RDN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d1 83 ec 10 31 c9 89 ca 89 45 bc 89 55 c0 89 4d c4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zenpak_RDN_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 39 53 0f 94 c3 8b 95 e4 fe ff ff 80 3a 54 0f 94 c7 20 fb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}