
rule PWS_Win32_Steam_Q_bit{
	meta:
		description = "PWS:Win32/Steam.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 33 2e 32 34 38 2e 31 38 36 2e 39 35 3a 39 30 2f 6a 69 65 73 68 6f 75 73 74 65 61 6d 2e 70 68 70 } //1 43.248.186.95:90/jieshousteam.php
		$a_01_1 = {73 74 65 61 6d 63 6c 69 65 6e 74 2e 64 6c 6c } //1 steamclient.dll
		$a_01_2 = {23 69 6e 5f 70 61 73 73 77 6f 72 64 } //1 #in_password
		$a_01_3 = {23 6d 62 5f 63 72 69 74 69 63 61 6c } //1 #mb_critical
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}