
rule Trojan_Win32_Jalapeno_ARA_MTB{
	meta:
		description = "Trojan:Win32/Jalapeno.ARA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 00 65 00 77 00 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 66 00 72 00 6f 00 6d 00 20 00 67 00 74 00 62 00 75 00 69 00 6c 00 64 00 65 00 72 00 20 00 31 00 2e 00 30 00 20 00 49 00 50 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 3a 00 } //2 New victim from gtbuilder 1.0 IP Address:
		$a_01_1 = {61 00 48 00 52 00 30 00 63 00 48 00 4d 00 36 00 4c 00 79 00 39 00 6b 00 61 00 58 00 4e 00 6a 00 62 00 33 00 4a 00 6b 00 4c 00 6d 00 4e 00 76 00 62 00 53 00 39 00 68 00 63 00 47 00 6b 00 76 00 64 00 32 00 56 00 69 00 61 00 47 00 39 00 76 00 61 00 33 00 4d 00 76 00 4d 00 54 00 49 00 } //2 aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}