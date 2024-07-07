
rule Trojan_Win32_Farfli_NF_MTB{
	meta:
		description = "Trojan:Win32/Farfli.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 39 37 64 6d 75 2e 6e 65 74 } //1 www.97dmu.net
		$a_01_1 = {53 6b 6b 6f 6a 66 20 68 71 61 6f 79 } //1 Skkojf hqaoy
		$a_01_2 = {57 73 75 77 6b 62 20 61 73 62 6d 6d 79 72 79 } //1 Wsuwkb asbmmyry
		$a_01_3 = {39 37 6d 75 2e 66 33 33 32 32 2e 6f 72 67 } //1 97mu.f3322.org
		$a_01_4 = {57 69 6e 64 6f 77 73 20 4f 6d 61 71 67 6b } //1 Windows Omaqgk
		$a_01_5 = {4f 6b 62 79 71 63 65 2e 65 78 65 } //1 Okbyqce.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}