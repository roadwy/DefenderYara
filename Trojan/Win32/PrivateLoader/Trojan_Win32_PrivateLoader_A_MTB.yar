
rule Trojan_Win32_PrivateLoader_A_MTB{
	meta:
		description = "Trojan:Win32/PrivateLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f1 66 c1 ca 90 01 01 66 85 ee 0f bb d1 8b 4d 90 01 01 66 c1 e2 90 01 01 66 8b d1 f9 85 c7 66 c1 ea 05 66 85 cc f8 66 81 fd 90 01 02 66 2b ca 66 89 8c 5f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}