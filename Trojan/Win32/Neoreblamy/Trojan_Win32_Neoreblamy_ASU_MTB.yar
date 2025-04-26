
rule Trojan_Win32_Neoreblamy_ASU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 4f 42 48 43 6f 62 4b 63 55 53 6b 52 56 6e 77 59 41 66 75 57 51 71 6f 5a 65 6b 75 6b 5a } //1 COBHCobKcUSkRVnwYAfuWQqoZekukZ
		$a_01_1 = {73 49 6f 6c 62 64 57 49 57 51 4d 61 4a 52 44 4d 65 42 41 49 78 77 46 77 65 66 44 6a } //1 sIolbdWIWQMaJRDMeBAIxwFwefDj
		$a_01_2 = {43 7a 65 6a 42 49 55 61 74 4a 4b 58 7a 59 4e 42 44 42 45 48 59 72 72 47 50 4c 64 69 4f 74 42 78 70 6c } //1 CzejBIUatJKXzYNBDBEHYrrGPLdiOtBxpl
		$a_01_3 = {4b 77 6d 54 72 6f 66 56 69 77 71 53 4d 55 64 7a 66 6b 6b 75 67 43 78 79 71 78 61 4f 4d } //1 KwmTrofViwqSMUdzfkkugCxyqxaOM
		$a_01_4 = {6f 50 47 61 63 73 43 4a 59 4f 41 73 5a 42 56 55 56 7a 48 4e 55 6a 44 71 5a 7a 56 68 68 78 } //1 oPGacsCJYOAsZBVUVzHNUjDqZzVhhx
		$a_01_5 = {76 6d 42 41 52 64 4e 54 44 55 48 6a 62 57 4b 4e 6a 4e 4f 67 67 52 6a 77 78 4a 71 6f } //1 vmBARdNTDUHjbWKNjNOggRjwxJqo
		$a_01_6 = {7a 62 76 41 45 6c 5a 73 57 6b 79 7a 64 57 56 67 43 69 73 50 53 64 41 69 61 } //1 zbvAElZsWkyzdWVgCisPSdAia
		$a_01_7 = {44 68 6d 46 50 51 6e 6d 76 4a 75 6c 7a 59 41 52 64 41 68 50 6e 62 6b 54 5a 46 59 58 42 75 } //1 DhmFPQnmvJulzYARdAhPnbkTZFYXBu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}