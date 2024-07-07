
rule Trojan_Win32_Graftor_SPDX_MTB{
	meta:
		description = "Trojan:Win32/Graftor.SPDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 14 8a 43 00 81 c3 70 22 0c ee 81 c3 67 26 6c 9d bb 57 37 53 02 e8 90 01 04 bb c4 5e 62 4a 29 fb 47 31 0e bb 5d 00 45 9e 81 c6 01 00 00 00 68 56 82 44 79 8b 3c 24 83 c4 04 4b 57 5b 39 d6 75 be 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}