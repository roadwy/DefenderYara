
rule Trojan_Win32_Amadey_AMD_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 8d 4d e8 51 50 56 ff 75 b4 ff d3 8d 45 ec 50 ff 75 ec 56 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AMD_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d0 8b 75 d4 8b 55 b0 8b 14 95 c8 e3 41 00 03 d1 8a 0c 03 03 d3 43 88 4c 32 2e 8b 4d bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AMD_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 b8 0b 00 00 ff d7 ff 35 ?? bc 46 00 ff d6 6a 00 6a 01 6a 02 ff 15 ?? ?? ?? ?? 6a 10 8d 4c 24 14 a3 ?? bc 46 00 51 50 ff 15 } //3
		$a_01_1 = {6a 00 6a 00 6a 00 6a 01 6a 00 ff 15 b8 12 45 00 89 45 d0 83 7d 1c 10 8d 4d 08 6a 00 0f 43 4d 08 6a 00 6a 03 6a 00 6a 00 6a 50 51 50 ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Amadey_AMD_MTB_4{
	meta:
		description = "Trojan:Win32/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 d2 2a d0 80 f2 44 2a ca 8a d0 80 f1 af 2a d1 0f b6 c8 d0 ca 2a d0 69 c9 fe 00 00 00 32 d0 f6 d2 80 c2 1a c0 ca 02 80 ea 57 32 d0 2a f2 b2 7d d0 c6 02 f0 f6 de 32 f0 02 f0 80 f6 09 2a ce f6 d1 02 c8 c0 c1 02 f6 d1 32 c8 80 e9 06 c0 c1 02 32 c8 80 c1 25 c0 c9 03 2a c8 d0 c9 80 e9 41 32 c8 80 c1 07 c0 c9 03 80 e9 56 32 c8 02 c8 f6 d9 32 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}