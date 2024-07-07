
rule PWS_Win32_Scofted{
	meta:
		description = "PWS:Win32/Scofted,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 70 77 66 69 6c 65 2e 6c 6f 67 00 } //1
		$a_01_1 = {5c 6c 6f 67 65 6e 63 72 79 70 74 2e 6c 6f 67 00 } //1
		$a_01_2 = {43 6f 64 65 73 6f 66 74 20 50 57 20 53 74 65 61 6c 65 72 } //2 Codesoft PW Stealer
		$a_01_3 = {46 54 50 20 50 61 73 73 77 6f 72 64 20 53 74 65 61 6c 65 72 } //1 FTP Password Stealer
		$a_01_4 = {46 6c 61 73 68 46 58 50 20 55 73 65 72 64 61 74 65 6e 3a } //1 FlashFXP Userdaten:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}