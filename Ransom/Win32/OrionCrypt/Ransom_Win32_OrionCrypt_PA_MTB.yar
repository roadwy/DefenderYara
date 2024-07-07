
rule Ransom_Win32_OrionCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/OrionCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 00 72 00 69 00 6f 00 6e 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //1 OrionRansomware.exe
		$a_01_1 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //1 %userappdata%\RestartApp.exe
		$a_01_2 = {63 6f 6e 74 61 63 74 20 69 6e 66 6f 40 6f 72 65 61 6e 73 2e 63 6f 6d } //1 contact info@oreans.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}