
rule Trojan_BAT_DarkStealer_DB_MTB{
	meta:
		description = "Trojan:BAT/DarkStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 35 31 32 65 39 31 33 64 2d 31 63 35 61 2d 34 34 64 31 2d 62 63 37 65 2d 61 37 63 65 35 63 66 63 64 64 32 35 } //1 $512e913d-1c5a-44d1-bc7e-a7ce5cfcdd25
		$a_81_1 = {43 53 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 CS.My.Resources
		$a_81_2 = {43 53 2e 66 72 6d 50 61 72 69 73 68 2e 72 65 73 6f 75 72 63 65 73 } //1 CS.frmParish.resources
		$a_81_3 = {4d 61 73 61 6b 61 } //1 Masaka
		$a_81_4 = {50 61 72 69 73 68 20 4d 61 6e 61 67 65 72 } //1 Parish Manager
		$a_81_5 = {4d 61 74 72 69 6d 6f 6e 79 20 4d 61 72 72 69 61 67 65 } //1 Matrimony Marriage
		$a_81_6 = {43 53 2e 52 65 70 6f 72 74 31 2e 72 64 6c 63 } //1 CS.Report1.rdlc
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}