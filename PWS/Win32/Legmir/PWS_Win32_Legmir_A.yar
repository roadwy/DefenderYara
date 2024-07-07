
rule PWS_Win32_Legmir_A{
	meta:
		description = "PWS:Win32/Legmir.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_1 = {41 55 54 48 20 4c 4f 47 49 4e } //1 AUTH LOGIN
		$a_01_2 = {52 43 50 54 20 54 4f 3a 20 3c } //1 RCPT TO: <
		$a_01_3 = {4d 41 49 4c 20 46 52 4f 4d 3a } //1 MAIL FROM:
		$a_01_4 = {4d 53 5f 44 6f 73 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 卍䑟獯搮汬䐀汬慃啮汮慯乤睯
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}