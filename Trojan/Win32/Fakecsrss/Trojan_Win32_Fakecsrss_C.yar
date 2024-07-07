
rule Trojan_Win32_Fakecsrss_C{
	meta:
		description = "Trojan:Win32/Fakecsrss.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 65 e0 00 c7 45 f8 90 01 04 c1 eb 1a 81 6d f8 90 01 04 81 45 f8 90 01 04 c1 e0 00 81 6d f8 90 01 04 81 45 f8 90 01 04 c1 e8 1f 81 6d f8 90 01 04 c1 e0 0b 81 45 f8 90 01 04 b8 90 01 04 81 6d f8 90 01 04 35 90 01 04 81 45 f8 90 01 04 c1 eb 02 81 45 f8 90 01 04 d1 e3 d1 e0 81 6d f8 90 01 04 81 e3 90 01 04 81 45 f8 90 01 04 83 65 dc 00 eb 09 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}