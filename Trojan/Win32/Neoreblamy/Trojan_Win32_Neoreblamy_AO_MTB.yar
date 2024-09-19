
rule Trojan_Win32_Neoreblamy_AO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 64 5a 66 41 6f 55 77 79 6d 59 63 4b 44 79 76 68 57 4f 62 59 73 4c 64 57 79 47 50 42 55 } //1 cdZfAoUwymYcKDyvhWObYsLdWyGPBU
		$a_01_1 = {63 54 4f 5a 46 4a 48 64 78 4c 50 76 75 65 4e 4f 6a 43 6c 41 51 55 4e 70 66 6e 6e 58 } //1 cTOZFJHdxLPvueNOjClAQUNpfnnX
		$a_01_2 = {66 4f 4f 75 66 6d 47 6e 71 49 41 42 51 70 6e 59 67 59 50 71 6d 4f 55 66 4f 72 66 51 } //1 fOOufmGnqIABQpnYgYPqmOUfOrfQ
		$a_01_3 = {75 65 4e 71 44 6a 69 68 46 5a 62 6d 46 4f 47 75 76 6c 62 44 66 51 47 62 4c 6f 57 62 } //1 ueNqDjihFZbmFOGuvlbDfQGbLoWb
		$a_01_4 = {48 77 58 46 66 53 53 79 63 69 71 77 42 4c 6a 6b 57 4f 67 79 58 58 73 62 54 41 61 57 4e 59 } //1 HwXFfSSyciqwBLjkWOgyXXsbTAaWNY
		$a_01_5 = {7a 6c 58 42 57 45 45 61 48 4e 74 78 74 52 69 56 52 4e 77 67 4e 5a 72 6e 6b 77 5a 57 53 } //1 zlXBWEEaHNtxtRiVRNwgNZrnkwZWS
		$a_01_6 = {7a 6c 6b 56 56 49 45 4f 49 62 4a 48 56 64 44 65 70 75 44 44 63 64 51 5a 67 47 43 73 63 } //1 zlkVVIEOIbJHVdDepuDDcdQZgGCsc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}