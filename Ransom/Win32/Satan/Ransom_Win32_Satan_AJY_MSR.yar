
rule Ransom_Win32_Satan_AJY_MSR{
	meta:
		description = "Ransom:Win32/Satan.AJY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 6f 6d 65 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Some files have been encrypted
		$a_81_1 = {45 6d 61 69 6c 3a 64 62 67 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 Email:dbger@protonmail.com
		$a_81_2 = {43 3a 5c 5f 48 6f 77 5f 74 6f 5f 64 65 63 72 79 70 74 5f 66 69 6c 65 73 2e 74 78 74 } //1 C:\_How_to_decrypt_files.txt
		$a_81_3 = {49 66 20 79 6f 75 20 65 78 63 65 65 64 20 74 68 65 20 70 61 79 6d 65 6e 74 20 74 69 6d 65 2c 20 79 6f 75 72 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 6f 70 65 6e 20 74 6f 20 74 68 65 20 70 75 62 6c 69 63 20 64 6f 77 6e 6c 6f 61 64 } //1 If you exceed the payment time, your data will be open to the public download
		$a_81_4 = {44 42 47 45 52 41 50 50 } //1 DBGERAPP
		$a_81_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 65 62 4d 6f 6e 65 79 5c 5b 64 62 67 65 72 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d 5d 5f 5f 65 6d 70 74 79 2e 64 62 67 65 72 } //1 C:\Program Files\WebMoney\[dbger@protonmail.com]__empty.dbger
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}