
rule Trojan_Win32_Mufila_DSK_MTB{
	meta:
		description = "Trojan:Win32/Mufila.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 e3 87 8c e1 53 81 6c 24 90 01 01 c8 ca 28 19 81 44 24 90 01 01 14 f5 1d 2e 35 d1 9b c8 6f 35 a9 77 64 56 81 6c 24 90 01 01 b8 f4 e0 60 c1 e0 17 81 44 24 90 01 01 b8 f4 e0 60 c1 e8 1e 81 6c 24 90 01 01 74 e0 1d 44 81 44 24 90 01 01 74 e0 1d 44 81 6c 24 90 01 01 6e 6b 98 45 90 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}