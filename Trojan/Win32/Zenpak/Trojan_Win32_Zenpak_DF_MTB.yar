
rule Trojan_Win32_Zenpak_DF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0f 01 d9 81 ee 90 02 04 21 f1 8b 75 e0 8b 5d bc 8a 34 1e 32 34 0f 8b 4d d8 88 34 19 8b 4d b8 8b 75 f0 39 f1 8b 4d b0 8b 75 b8 8b 7d a8 89 4d dc 89 7d cc 89 75 d0 0f 84 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}