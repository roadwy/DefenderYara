
rule TrojanSpy_BAT_Limlotti_A{
	meta:
		description = "TrojanSpy:BAT/Limlotti.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 00 2d 00 3a 00 3a 00 5d 00 } //01 00  --::]
		$a_01_1 = {53 00 65 00 74 00 45 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 } //01 00  SetEPASSWORD
		$a_01_2 = {46 00 54 00 50 00 55 00 70 00 6c 00 6f 00 61 00 64 00 } //01 00  FTPUpload
		$a_00_3 = {4c 00 69 00 6d 00 69 00 74 00 6c 00 65 00 73 00 73 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 3a 00 20 00 3a 00 20 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 52 00 65 00 63 00 6f 00 72 00 64 00 73 00 20 00 3a 00 20 00 3a 00 } //01 00  Limitless Logger : : Keyboard Records : :
		$a_00_4 = {42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //00 00  Bitcoin
	condition:
		any of ($a_*)
 
}