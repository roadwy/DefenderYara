
rule PWS_Win32_Mocrt_A_MTB{
	meta:
		description = "PWS:Win32/Mocrt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //01 00  SELECT * FROM logins
		$a_01_1 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //01 00  \Google\Chrome\User Data\Default\Login Data
		$a_01_2 = {5c 00 4d 00 6f 00 72 00 74 00 79 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 5c 00 } //01 00  \MortyCrypter\
		$a_01_3 = {5c 00 72 00 64 00 70 00 77 00 72 00 61 00 70 00 2e 00 69 00 6e 00 69 00 } //01 00  \rdpwrap.ini
		$a_01_4 = {48 00 65 00 79 00 20 00 49 00 27 00 6d 00 20 00 41 00 64 00 6d 00 69 00 6e 00 } //00 00  Hey I'm Admin
	condition:
		any of ($a_*)
 
}