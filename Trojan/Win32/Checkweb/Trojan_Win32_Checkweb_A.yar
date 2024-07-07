
rule Trojan_Win32_Checkweb_A{
	meta:
		description = "Trojan:Win32/Checkweb.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 55 53 45 52 00 50 41 53 53 00 4c 49 53 54 00 61 6e 6f 6e 79 6d 6f 75 73 00 58 3d 25 73 20 55 3d 25 73 20 4f 3d 25 73 20 48 3d 25 64 20 56 3d 25 64 20 45 3d } //1
		$a_01_1 = {7b 45 36 46 42 35 45 32 30 2d 44 45 33 35 2d 31 31 43 46 2d 39 43 38 37 2d 30 30 41 41 30 30 35 31 32 37 45 44 7d 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 {E6FB5E20-DE35-11CF-9C87-00AA005127ED}\InProcServer32
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 69 63 71 2e 63 6f 6d 2f 70 65 6f 70 6c 65 2f } //1 https://www.icq.com/people/
		$a_01_3 = {57 65 62 4d 6f 6e 65 79 } //1 WebMoney
		$a_01_4 = {33 fa 23 fb 33 fa 03 c6 03 c7 c1 c0 03 8b fb 8b 75 04 33 f9 23 f8 33 f9 03 d6 03 d7 c1 c2 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}