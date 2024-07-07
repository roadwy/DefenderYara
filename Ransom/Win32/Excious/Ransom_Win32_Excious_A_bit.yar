
rule Ransom_Win32_Excious_A_bit{
	meta:
		description = "Ransom:Win32/Excious.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d } //3 www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
		$a_01_1 = {25 73 5c 25 73 2e 6c 6f 63 6b 79 } //1 %s\%s.locky
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 20 61 6c 6c 20 2f 20 71 75 69 65 74 } //1 vssadmin.exe vssadmin delete shadows / all / quiet
		$a_01_3 = {40 57 61 6e 61 44 65 63 72 79 70 74 6f 72 40 2e 65 78 65 } //1 @WanaDecryptor@.exe
		$a_01_4 = {69 63 61 63 6c 73 20 2e 20 2f 20 67 72 61 6e 74 20 45 76 65 72 79 6f 6e 65 20 3a 20 46 20 2f 20 54 20 2f 20 43 20 2f 20 51 } //1 icacls . / grant Everyone : F / T / C / Q
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}