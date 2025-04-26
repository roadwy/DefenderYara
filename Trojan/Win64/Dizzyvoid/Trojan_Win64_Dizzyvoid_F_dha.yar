
rule Trojan_Win64_Dizzyvoid_F_dha{
	meta:
		description = "Trojan:Win64/Dizzyvoid.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 25 73 } //1 Global\%s
		$a_01_1 = {41 61 42 62 43 63 44 64 45 65 46 66 47 67 48 68 49 69 4a 6a 4b 6b 4c 6c 4d 6d 4e 6e 4f 6f 50 70 51 71 52 72 53 73 54 74 55 75 56 76 57 77 58 78 59 79 5a 7a 30 31 32 33 34 35 36 37 38 39 } //1 AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789
		$a_01_2 = {68 74 74 70 64 2e 65 78 65 } //1 httpd.exe
		$a_01_3 = {53 74 61 72 74 57 6f 72 6b } //1 StartWork
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}