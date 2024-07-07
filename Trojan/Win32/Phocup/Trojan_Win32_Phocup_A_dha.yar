
rule Trojan_Win32_Phocup_A_dha{
	meta:
		description = "Trojan:Win32/Phocup.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,63 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {35 00 34 00 2e 00 33 00 36 00 2e 00 31 00 39 00 2e 00 31 00 37 00 34 00 } //1 54.36.19.174
		$a_01_1 = {4e 00 54 00 51 00 75 00 4d 00 7a 00 59 00 75 00 4d 00 54 00 6b 00 75 00 4d 00 54 00 63 00 30 00 } //1 NTQuMzYuMTkuMTc0
		$a_01_2 = {55 00 30 00 4c 00 6a 00 4d 00 32 00 4c 00 6a 00 45 00 35 00 4c 00 6a 00 45 00 33 00 4e 00 } //1 U0LjM2LjE5LjE3N
		$a_01_3 = {31 00 4e 00 43 00 34 00 7a 00 4e 00 69 00 34 00 78 00 4f 00 53 00 34 00 78 00 4e 00 7a 00 } //1 1NC4zNi4xOS4xNz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}