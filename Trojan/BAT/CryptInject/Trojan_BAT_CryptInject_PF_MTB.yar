
rule Trojan_BAT_CryptInject_PF_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 11 04 8f 90 01 04 25 71 90 01 04 07 11 04 91 61 d2 81 90 01 04 02 7b 90 00 } //01 00 
		$a_03_1 = {11 04 17 6f 90 02 06 11 04 8f 90 01 04 25 71 90 01 04 08 11 04 91 61 d2 81 90 01 04 11 04 17 58 13 04 11 04 07 8e 69 32 b2 90 00 } //01 00 
		$a_03_2 = {08 11 04 7e 90 01 04 6f 90 02 06 11 04 8f 90 01 04 25 71 90 01 04 08 11 04 91 61 d2 81 90 01 04 11 04 7e 90 01 04 58 13 04 11 04 07 8e 69 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CryptInject_PF_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 33 36 36 32 33 66 66 63 2d 36 63 33 30 2d 34 64 65 62 2d 39 37 62 35 2d 35 38 37 36 32 31 39 35 33 37 61 39 } //01 00  $36623ffc-6c30-4deb-97b5-5876219537a9
		$a_81_1 = {50 61 74 63 68 69 } //01 00  Patchi
		$a_81_2 = {54 6f 62 6c 65 72 6f 6e 65 } //01 00  Toblerone
		$a_81_3 = {43 61 64 62 75 72 79 20 47 69 66 74 73 20 44 69 72 65 63 74 2e } //01 00  Cadbury Gifts Direct.
		$a_81_4 = {64 62 6f 2e 44 6f 63 74 6f 72 73 } //01 00  dbo.Doctors
		$a_81_5 = {64 62 6f 2e 50 61 74 69 65 6e 74 73 } //01 00  dbo.Patients
		$a_81_6 = {64 62 6f 2e 50 61 74 69 65 6e 74 5f 41 64 6d 69 73 73 69 6f 6e 73 } //00 00  dbo.Patient_Admissions
	condition:
		any of ($a_*)
 
}