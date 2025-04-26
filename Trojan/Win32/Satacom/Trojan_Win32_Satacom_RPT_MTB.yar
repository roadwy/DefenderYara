
rule Trojan_Win32_Satacom_RPT_MTB{
	meta:
		description = "Trojan:Win32/Satacom.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc c7 45 e0 25 06 00 00 c7 45 dc d4 e1 00 00 c7 45 d8 00 3e 00 00 c7 45 d4 24 06 00 00 c7 45 f0 04 00 00 00 c7 45 d0 81 68 02 00 c7 45 cc 23 df 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}