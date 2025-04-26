
rule Trojan_Win32_Dnoper_ND_MTB{
	meta:
		description = "Trojan:Win32/Dnoper.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 57 69 6d 4c 67 5a 75 55 75 50 55 70 73 68 57 4b 63 51 49 4f 66 35 4d 7a 42 4d 6e 46 4d 35 66 47 4f 6f 41 71 4a 4e 33 5a 4a 2e 62 61 74 } //1 rWimLgZuUuPUpshWKcQIOf5MzBMnFM5fGOoAqJN3ZJ.bat
		$a_01_1 = {41 71 4a 4e 33 5a 4a 2e 62 61 74 } //1 AqJN3ZJ.bat
		$a_01_2 = {50 79 4a 66 70 52 33 57 50 2e 76 62 65 } //1 PyJfpR3WP.vbe
		$a_01_3 = {72 6f 6b 65 72 44 6c 6c 53 76 63 2e 65 78 65 } //1 rokerDllSvc.exe
		$a_01_4 = {42 72 6f 6b 65 72 44 6c 6c 53 76 63 2e 65 78 65 } //1 BrokerDllSvc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}