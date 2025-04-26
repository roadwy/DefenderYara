
rule Trojan_Win32_Fragtor_NO_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 09 ff 89 59 08 80 61 24 80 8a 41 24 24 7f 88 41 24 66 c7 41 25 0a 0a 89 59 38 88 59 34 83 c1 40 89 4d dc } //2
		$a_01_1 = {d0 e5 d0 fd d0 c5 8a c5 24 0f d7 8a e0 d0 e1 d0 f9 d0 c1 8a c1 24 0f d7 d0 e4 d0 e4 0a c4 } //1
		$a_01_2 = {4e 57 56 78 4e 63 54 7a 50 42 6b 4c 7a 4e 72 4d 64 72 76 4b 77 46 6c 78 58 4d 58 66 45 71 4e 55 6d 62 } //1 NWVxNcTzPBkLzNrMdrvKwFlxXMXfEqNUmb
		$a_01_3 = {72 46 41 51 4f 44 52 49 54 4e 44 70 69 43 7a 76 43 48 66 56 43 74 53 53 6a 6b 4b 7a 6a } //1 rFAQODRITNDpiCzvCHfVCtSSjkKzj
		$a_01_4 = {58 70 69 78 76 4d 61 6a 53 6f 45 68 75 4b 6d 63 68 53 53 52 79 } //1 XpixvMajSoEhuKmchSSRy
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}