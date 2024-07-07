
rule Trojan_Win32_Fareit_V_MTB{
	meta:
		description = "Trojan:Win32/Fareit.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 03 d0 73 90 01 06 80 32 98 40 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_V_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 14 10 f7 ef 03 d7 80 f1 90 01 01 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 88 0c 32 8a 04 2e 3c 90 01 01 77 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_V_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 3e 46 90 09 05 00 e8 90 00 } //2
		$a_02_1 = {55 8b ec a1 90 01 04 69 c0 90 01 04 83 ec 90 01 01 6a 90 01 01 6a 90 01 01 05 90 01 04 6a 90 01 01 a3 90 01 04 ff 15 90 02 10 8d 4d a0 51 6a 90 01 01 6a 90 01 01 e8 90 01 04 0f b7 05 90 01 04 25 90 01 04 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}