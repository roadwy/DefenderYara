
rule Trojan_Win32_Baidence_MA_MTB{
	meta:
		description = "Trojan:Win32/Baidence.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 39 54 48 38 41 64 78 2e 65 78 65 } //2 O9TH8Adx.exe
		$a_01_1 = {36 4e 53 70 79 57 57 64 2e 65 78 65 } //2 6NSpyWWd.exe
		$a_01_2 = {43 6f 6f 6b 69 65 3a 20 42 41 49 44 55 49 44 3d 34 35 35 31 42 33 41 38 37 33 33 31 30 41 31 44 39 46 31 44 38 46 33 38 34 37 46 41 44 41 35 32 } //1 Cookie: BAIDUID=4551B3A873310A1D9F1D8F3847FADA52
		$a_01_3 = {2f 3f 72 3d 73 69 74 65 2f 47 65 74 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 /?r=site/GetController
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}