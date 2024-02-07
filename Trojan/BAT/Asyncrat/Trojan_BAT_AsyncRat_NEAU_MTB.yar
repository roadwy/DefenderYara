
rule Trojan_BAT_AsyncRat_NEAU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 42 48 41 55 5a 37 57 48 41 5a } //03 00  get_BHAUZ7WHAZ
		$a_01_1 = {67 65 74 5f 4f 5a 49 41 38 48 41 5a 49 } //03 00  get_OZIA8HAZI
		$a_01_2 = {63 61 62 61 65 34 65 65 36 65 33 61 31 61 39 37 61 38 36 30 62 39 64 63 65 38 38 35 31 36 33 38 31 } //01 00  cabae4ee6e3a1a97a860b9dce88516381
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}