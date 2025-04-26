
rule Trojan_Win32_Sirefef_AK{
	meta:
		description = "Trojan:Win32/Sirefef.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 73 65 6e 64 74 90 01 01 3d 72 65 63 76 74 } //1
		$a_01_1 = {5c 25 30 38 78 2e 40 } //1 \%08x.@
		$a_03_2 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 90 09 10 00 00 24 00 00 } //1
		$a_03_3 = {d1 37 0c 1e 3f a3 64 1e 2b d7 a6 ea c7 e7 18 c1 90 09 10 00 00 a4 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Sirefef_AK_2{
	meta:
		description = "Trojan:Win32/Sirefef.AK,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 73 65 6e 64 74 90 01 01 3d 72 65 63 76 74 } //1
		$a_01_1 = {5c 25 30 38 78 2e 40 } //1 \%08x.@
		$a_03_2 = {8b 55 14 04 b6 e4 37 bf bb 01 aa 9a b0 d2 0a 33 90 09 10 00 00 24 00 00 } //1
		$a_03_3 = {d1 37 0c 1e 3f a3 64 1e 2b d7 a6 ea c7 e7 18 c1 90 09 10 00 00 a4 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}