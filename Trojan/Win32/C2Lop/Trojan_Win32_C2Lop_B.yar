
rule Trojan_Win32_C2Lop_B{
	meta:
		description = "Trojan:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 55 57 8b 1f 8b 4f 04 ba b9 79 90 03 01 01 37 39 9e 8b c2 c1 e0 04 bf 10 00 00 00 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_C2Lop_B_2{
	meta:
		description = "Trojan:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 61 64 20 45 6c 6d 6f } //10 Bad Elmo
		$a_01_1 = {59 6f 75 20 6d 75 73 74 20 69 6e 73 74 61 6c 6c 20 74 68 69 73 20 73 6f 66 74 77 61 72 65 20 61 73 20 70 61 72 74 20 6f 66 20 74 68 65 20 70 61 72 65 6e 74 20 70 72 6f 67 72 61 6d } //10 You must install this software as part of the parent program
		$a_01_2 = {53 77 49 63 65 72 74 69 66 69 45 64 } //1 SwIcertifiEd
		$a_01_3 = {2d 43 75 72 6c 20 25 73 20 2d 4d 70 58 25 73 } //1 -Curl %s -MpX%s
		$a_10_4 = {43 61 73 69 6e 6f 20 4f 6e 6c 69 6e 65 } //1 Casino Online
		$a_10_5 = {57 65 62 20 48 6f 73 74 69 6e 67 7c 68 6f 73 74 69 6e 67 } //1 Web Hosting|hosting
		$a_10_6 = {50 65 6e 69 73 20 45 6e 6c 61 72 67 65 6d 65 6e 74 7c 50 65 6e 69 73 20 45 6e 6c 61 72 67 65 6d 65 6e 74 20 50 69 6c 6c } //1 Penis Enlargement|Penis Enlargement Pill
		$a_10_7 = {42 75 79 20 56 69 61 67 72 61 73 } //1 Buy Viagras
		$a_10_8 = {41 64 75 6c 74 20 45 64 75 63 61 74 69 6f 6e } //1 Adult Education
		$a_10_9 = {42 72 65 61 73 74 20 45 6e 68 61 6e 63 65 6d 65 6e 74 } //1 Breast Enhancement
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_10_4  & 1)*1+(#a_10_5  & 1)*1+(#a_10_6  & 1)*1+(#a_10_7  & 1)*1+(#a_10_8  & 1)*1+(#a_10_9  & 1)*1) >=22
 
}
rule Trojan_Win32_C2Lop_B_3{
	meta:
		description = "Trojan:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 55 57 8b 1f 8b 4f 04 ba b9 79 38 9e 8b c2 c1 e0 04 bf 10 00 00 00 8b eb c1 e5 04 2b cd 8b 6e 08 33 eb 2b cd 8b eb c1 ed 05 33 e8 2b cd 2b 4e 0c 8b e9 c1 e5 04 2b dd 8b 2e 33 e9 2b dd 8b e9 c1 ed 05 33 e8 2b dd 2b 5e 04 2b c2 4f 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_C2Lop_B_4{
	meta:
		description = "Trojan:Win32/C2Lop.B,SIGNATURE_TYPE_PEHSTR,20 00 20 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 72 69 6e 69 74 79 61 63 71 75 69 73 69 74 69 6f 6e 73 2e 63 6f 6d } //10 trinityacquisitions.com
		$a_01_1 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 79 6f 75 72 20 70 61 73 73 77 6f 72 64 3a } //10 Please enter your password:
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 73 63 61 70 65 5c } //10 Software\Netscape\
		$a_01_3 = {5c 4d 50 33 20 4d 75 73 69 63 20 53 65 61 72 63 68 2e 6c 6e 6b } //1 \MP3 Music Search.lnk
		$a_01_4 = {25 73 2f 73 65 61 72 63 68 2f 73 65 61 72 63 68 2e 63 67 69 3f 73 3d } //1 %s/search/search.cgi?s=
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 25 73 2f 73 65 61 72 63 68 62 61 72 2e 68 74 6d 6c } //1 http://www.%s/searchbar.html
		$a_01_6 = {47 61 79 20 61 6e 64 20 4c 65 73 62 69 61 6e } //1 Gay and Lesbian
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 70 2e 63 6f 6d 2f 73 65 61 72 63 68 2f } //1 http://www.lop.com/search/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=32
 
}