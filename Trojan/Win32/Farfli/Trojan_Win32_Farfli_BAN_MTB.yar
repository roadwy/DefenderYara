
rule Trojan_Win32_Farfli_BAN_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 35 36 35 2e 7a 69 70 } //1 C:\Users\Public\565.zip
		$a_01_1 = {31 32 33 2e 35 35 2e 38 39 2e 38 38 } //1 123.55.89.88
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 35 35 35 2e 7a 69 70 } //1 C:\Users\Public\555.zip
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 6c 75 73 21 5c 54 68 65 6d 65 73 5c 43 75 72 72 65 6e 74 } //1 Software\Microsoft\Plus!\Themes\Current
		$a_01_4 = {74 67 3a 2f 2f 73 65 74 6c 61 6e 67 75 61 67 65 3f } //1 tg://setlanguage?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}