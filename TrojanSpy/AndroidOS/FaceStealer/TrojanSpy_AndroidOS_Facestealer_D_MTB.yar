
rule TrojanSpy_AndroidOS_Facestealer_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Facestealer.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 69 63 6b 65 6e 46 61 63 65 62 6f 6f 6b } //01 00  ChickenFacebook
		$a_01_1 = {6d 5f 6c 6f 67 69 6e 5f 70 61 73 73 77 6f 72 64 } //01 00  m_login_password
		$a_01_2 = {6d 5f 6c 6f 67 69 6e 5f 65 6d 61 69 6c } //01 00  m_login_email
		$a_03_3 = {1a 00 00 00 1a 01 90 01 02 6e 20 90 01 02 15 00 0c 05 12 01 07 02 21 53 35 31 1c 00 22 03 90 01 02 70 10 90 01 02 03 00 6e 20 90 01 02 23 00 46 02 05 01 12 24 71 20 90 01 02 42 00 0a 02 8e 22 6e 20 90 01 02 23 00 6e 10 90 01 02 03 00 0c 02 d8 01 01 01 28 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}