
rule Trojan_AndroidOS_FakeInstSms_I{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.I,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 4a 6b 37 48 2f 50 77 63 44 2f 53 4c 59 66 6f 4d 64 47 } //01 00  LJk7H/PwcD/SLYfoMdG
		$a_00_1 = {6c 6f 61 64 53 6d 73 43 6f 75 6e 74 } //01 00  loadSmsCount
		$a_00_2 = {4c 6f 72 67 2f 4d 6f 62 69 6c 65 44 62 2f 4d 6f 62 69 6c 65 44 61 74 61 62 61 73 65 } //01 00  Lorg/MobileDb/MobileDatabase
		$a_00_3 = {6c 69 63 65 6e 73 65 57 69 74 68 4f 6e 65 42 75 74 74 6f 6e } //00 00  licenseWithOneButton
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}