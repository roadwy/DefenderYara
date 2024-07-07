
rule Trojan_Win32_Zlader_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zlader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 2a 8b 35 88 1c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 00 10 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d 9c 1c 41 00 76 c9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zlader_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Zlader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 83 c1 01 89 4d ec 8b 55 ec 3b 15 5c 50 40 00 73 2d 8b 45 ec 99 b9 0a 00 00 00 f7 f9 8b 45 f8 0f be 0c 10 8b 15 44 50 40 00 03 55 ec 0f be 02 33 c1 8b 0d 44 50 40 00 03 4d ec 88 01 eb bf } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}