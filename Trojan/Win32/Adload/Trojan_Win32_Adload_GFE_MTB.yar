
rule Trojan_Win32_Adload_GFE_MTB{
	meta:
		description = "Trojan:Win32/Adload.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {89 44 24 20 89 7c 24 1c 89 6c 24 18 89 5c 24 14 89 54 24 10 89 4c 24 0c 8b 44 24 24 89 44 24 08 c7 44 24 04 90 01 04 c7 04 24 94 e2 41 01 90 00 } //10
		$a_02_1 = {89 48 04 89 01 c7 80 ec ff 13 00 02 00 00 00 b9 90 01 04 29 f1 89 0d 90 01 04 ba 90 01 04 29 f2 8d 0c 02 89 0d fc bc 41 01 83 ce 02 89 74 02 fc eb 0c c7 05 f8 bc 41 01 00 00 00 00 31 c9 89 c8 83 c4 10 5e c3 90 00 } //10
		$a_80_2 = {42 44 43 72 65 61 74 6f 72 } //BDCreator  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}