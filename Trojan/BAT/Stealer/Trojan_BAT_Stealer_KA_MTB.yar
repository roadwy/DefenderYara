
rule Trojan_BAT_Stealer_KA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 6d 79 66 69 6c 65 2e 74 78 74 } //1 c:\myfile.txt
		$a_81_1 = {63 3a 5c 66 69 6c 65 5c 72 65 2e 62 61 74 } //1 c:\file\re.bat
		$a_81_2 = {48 3a 5c 72 65 61 64 65 72 2e 65 78 65 } //1 H:\reader.exe
		$a_81_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 72 65 61 64 65 72 2e 65 78 65 } //1 C:\Windows\reader.exe
		$a_01_4 = {24 39 35 31 30 30 36 61 37 2d 62 30 32 66 2d 34 33 62 30 2d 39 33 31 33 2d 66 39 34 38 66 32 38 61 62 35 66 61 } //1 $951006a7-b02f-43b0-9313-f948f28ab5fa
		$a_81_5 = {43 3a 5c 66 69 6c 65 5c 73 61 6d 2e 7a 69 70 } //1 C:\file\sam.zip
		$a_01_6 = {44 69 70 6f 73 65 48 6f 6f 6b } //1 DiposeHook
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}