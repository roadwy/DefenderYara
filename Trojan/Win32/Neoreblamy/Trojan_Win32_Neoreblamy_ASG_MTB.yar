
rule Trojan_Win32_Neoreblamy_ASG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 57 41 58 53 51 56 6f 6b 55 6b 78 66 7a 41 51 47 53 71 58 41 66 78 6b 54 4d 49 79 79 55 56 46 } //1 wWAXSQVokUkxfzAQGSqXAfxkTMIyyUVF
		$a_01_1 = {62 62 4f 7a 65 64 64 67 70 78 43 5a 64 73 41 76 69 49 65 77 54 64 5a 68 64 6e 66 73 6b 61 6d 48 6e 47 4e 4a 4a 65 63 61 67 } //1 bbOzeddgpxCZdsAviIewTdZhdnfskamHnGNJJecag
		$a_01_2 = {71 61 4e 4a 54 76 6a 50 59 64 45 46 67 55 47 63 56 50 4b 42 6f 51 6c 4b 49 77 52 79 5a 6d 48 } //1 qaNJTvjPYdEFgUGcVPKBoQlKIwRyZmH
		$a_01_3 = {61 6f 51 54 47 54 71 62 6d 58 76 49 75 59 44 6c 70 64 49 6a 6d 68 55 52 54 59 43 54 47 51 71 51 6a 55 } //1 aoQTGTqbmXvIuYDlpdIjmhURTYCTGQqQjU
		$a_01_4 = {79 6b 6c 77 5a 6d 68 4c 5a 6e 78 6b 6a 48 52 76 55 42 6c 51 41 57 77 4b 50 67 65 68 79 69 } //1 yklwZmhLZnxkjHRvUBlQAWwKPgehyi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}