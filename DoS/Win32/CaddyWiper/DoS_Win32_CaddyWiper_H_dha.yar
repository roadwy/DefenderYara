
rule DoS_Win32_CaddyWiper_H_dha{
	meta:
		description = "DoS:Win32/CaddyWiper.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 "
		
	strings :
		$a_43_0 = {7f 30 01 75 90 01 01 83 c7 50 33 c0 ab ab ab 53 ab 8d 85 90 01 04 50 53 53 68 80 07 00 00 ff b5 90 01 04 68 54 c0 07 00 ff 90 01 02 ff 90 00 64 } //100
		$a_53_1 = {74 46 c7 45 90 01 01 69 6c 65 50 c7 45 90 01 01 6f 69 6e 74 66 c7 45 90 01 01 65 72 90 00 00 00 5d 04 00 00 69 6c 05 80 5c 26 00 00 6a 6c 05 80 00 00 01 00 08 00 10 00 ac 21 57 69 6e 4c 4e 4b 2e 41 55 } //8192
	condition:
		((#a_43_0  & 1)*100+(#a_53_1  & 1)*8192) >=200
 
}