
rule Trojan_Win32_Satacom_RJ_MTB{
	meta:
		description = "Trojan:Win32/Satacom.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 06 c1 e8 08 33 d0 8b 45 fc 8b 0c 08 03 ca 8b 45 f8 33 d2 f7 75 f0 8b 45 10 03 0c 90 03 4d f8 ba 04 00 00 00 d1 e2 8b 45 fc 8b 14 10 2b d1 89 55 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}