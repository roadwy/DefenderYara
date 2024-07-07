
rule Trojan_Win32_QuasarRAT_A_MTB{
	meta:
		description = "Trojan:Win32/QuasarRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8b 44 85 d0 89 45 ec 8b 45 ec 89 04 24 e8 90 01 04 89 45 e8 8d 45 cc 89 44 24 08 8b 45 e8 89 44 24 04 8b 45 ec 89 04 24 e8 90 01 04 89 45 e4 83 7d e4 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}