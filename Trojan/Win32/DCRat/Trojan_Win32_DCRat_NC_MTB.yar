
rule Trojan_Win32_DCRat_NC_MTB{
	meta:
		description = "Trojan:Win32/DCRat.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6b 74 4f 67 41 75 32 30 6b 5a 66 4d 36 61 5a 54 7a 57 4c 68 6b 36 64 44 6c 7a 62 4b 69 2e 76 62 65 } //1 cktOgAu20kZfM6aZTzWLhk6dDlzbKi.vbe
		$a_01_1 = {65 63 6b 74 4f 67 41 75 32 30 6b 5a 66 4d 36 61 5a 54 7a 57 4c 68 6b 36 64 44 6c 7a 62 4b 69 2e 76 62 65 } //1 ecktOgAu20kZfM6aZTzWLhk6dDlzbKi.vbe
		$a_01_2 = {57 4c 68 6b 36 64 44 6c 7a 62 4b 69 2e 76 62 65 } //1 WLhk6dDlzbKi.vbe
		$a_01_3 = {73 65 72 76 65 72 57 65 62 42 72 6f 6b 65 72 2e 65 78 65 } //1 serverWebBroker.exe
		$a_01_4 = {44 72 69 76 65 72 6d 6f 6e 69 74 6f 72 43 6f 6d 6d 6f 6e } //1 DrivermonitorCommon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}