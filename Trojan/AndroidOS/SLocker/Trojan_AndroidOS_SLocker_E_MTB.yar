
rule Trojan_AndroidOS_SLocker_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SLocker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 73 73 73 70 2e 4d 79 41 64 6d 69 6e } //02 00 
		$a_00_1 = {63 6f 6d 2e 73 73 73 70 2e 73 } //01 00 
		$a_01_2 = {43 6a 4a 4a 65 6b 34 31 57 57 70 4e } //01 00 
		$a_01_3 = {72 65 73 65 74 50 61 73 73 77 6f 72 64 } //01 00 
		$a_01_4 = {6c 6f 67 63 61 74 20 2d 76 20 74 68 72 65 61 64 74 69 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}