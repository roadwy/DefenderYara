
rule Ransom_Win32_JSWorm_A_MTB{
	meta:
		description = "Ransom:Win32/JSWorm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 45 43 52 59 50 54 2e 68 74 61 } //1 DECRYPT.hta
		$a_01_1 = {4a 53 57 4f 52 4d } //1 JSWORM
		$a_01_2 = {2f 63 20 72 65 67 20 61 64 64 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 22 7a 61 70 69 73 6b 61 22 20 2f 64 20 22 } //1 /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "zapiska" /d "
		$a_01_3 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /c vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}