
rule Trojan_Win32_PersianRat_APR_MTB{
	meta:
		description = "Trojan:Win32/PersianRat.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 00 65 00 72 00 73 00 69 00 61 00 6e 00 } //1 Persian
		$a_01_1 = {44 48 5f 54 69 6e 79 4b 65 79 6c 6f 67 67 65 72 } //1 DH_TinyKeylogger
		$a_01_2 = {51 4d 61 6e 79 20 6f 66 20 79 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 76 69 64 65 6f 73 20 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 20 6c 6f 6e 67 65 72 } //1 QMany of your documents, photos, videos , databases and other files are no longer
		$a_01_3 = {4b 41 63 63 65 73 69 62 6c 65 20 42 65 63 61 75 73 65 20 54 68 65 79 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 2e 20 4d 61 79 62 65 20 59 6f 75 20 41 72 65 20 42 75 73 79 20 4c 6f 6f 6b 69 6e 67 20 46 6f 72 } //1 KAccesible Because They Have Been Encrypted. Maybe You Are Busy Looking For
		$a_01_4 = {59 41 20 57 61 79 20 54 6f 20 52 65 63 6f 76 65 72 20 59 6f 75 72 20 46 69 6c 65 73 2c 20 42 75 74 20 44 6f 20 4e 6f 74 20 57 61 73 74 65 20 59 6f 75 72 20 54 69 6d 65 2c 20 4e 6f 62 6f 64 79 20 43 61 6e 20 52 65 63 6f 76 65 72 20 46 69 6c 65 73 20 57 69 74 68 6f 75 74 } //1 YA Way To Recover Your Files, But Do Not Waste Your Time, Nobody Can Recover Files Without
		$a_01_5 = {37 69 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 } //1 7if you want to decrypt all your files, you need to pay
		$a_01_6 = {54 59 6f 75 20 43 61 6e 6e 6e 6f 74 20 44 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 2e 20 61 66 74 65 72 20 70 61 79 6d 65 6e 74 20 74 72 79 20 6e 6f 77 20 62 79 20 63 6c 69 63 6b 69 6e 67 } //1 TYou Cannnot Decrypt your files for free. after payment try now by clicking
		$a_01_7 = {59 59 6f 75 20 4f 6e 6c 79 20 48 61 76 65 20 33 20 44 61 79 73 20 74 6f 20 53 75 62 6d 69 74 20 74 68 65 20 70 61 79 6d 65 6e 74 2e 20 41 66 74 65 72 20 74 68 61 74 20 74 68 69 73 20 77 69 6e 64 6f 77 20 77 69 6c 6c 20 62 65 20 63 6c 6f 73 65 64 20 66 6f 72 65 76 65 72 } //1 YYou Only Have 3 Days to Submit the payment. After that this window will be closed forever
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}