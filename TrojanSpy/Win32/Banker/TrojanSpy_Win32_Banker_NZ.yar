
rule TrojanSpy_Win32_Banker_NZ{
	meta:
		description = "TrojanSpy:Win32/Banker.NZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 6c 61 6e 68 6f 75 73 65 2e 63 6f 6d 2e 62 72 2f 75 70 6c 6f 61 64 73 2f 73 6f 75 72 63 65 2f 77 69 6e 75 70 64 61 74 65 2e 65 78 65 } //1 uploadlanhouse.com.br/uploads/source/winupdate.exe
		$a_01_1 = {21 41 44 48 3a 52 43 34 2b 52 53 41 3a 2b 48 49 47 48 3a 2b 4d 45 44 49 55 4d 3a 2b 4c 4f 57 3a 2b 53 53 4c 76 32 3a 2b 45 58 50 } //1 !ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP
		$a_03_2 = {63 6d 64 20 2f 6b 20 63 3a 5c 67 6f 6f 67 6c 65 2d 69 6d 61 67 65 90 01 01 2e 67 69 66 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}