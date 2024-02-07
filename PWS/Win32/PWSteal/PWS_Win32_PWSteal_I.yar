
rule PWS_Win32_PWSteal_I{
	meta:
		description = "PWS:Win32/PWSteal.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //01 00  \Mozilla\Firefox\profiles.ini
		$a_01_1 = {46 69 72 65 66 6f 78 20 53 74 65 61 6c 65 72 } //01 00  Firefox Stealer
		$a_03_2 = {50 ff 55 e0 59 85 c0 0f 85 90 01 02 00 00 ff 55 d8 89 45 bc 83 7d bc 00 0f 84 90 01 02 00 00 6a 00 6a 01 8b 45 bc 50 ff 55 d4 83 c4 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}