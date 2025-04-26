
rule Trojan_Win32_Zenpak_BQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d ec 8b 75 d0 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 e0 89 4d dc 89 55 d8 0f } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}