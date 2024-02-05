
rule Trojan_AndroidOS_SmsSpy_D{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.D,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 70 6f 69 6e 74 72 65 77 61 72 64 61 73 2e 63 6f 2e 69 6e 2f 61 70 69 2f } //02 00 
		$a_01_1 = {70 72 65 66 4e 61 6d 65 55 53 45 52 4e 41 4d 45 } //02 00 
		$a_01_2 = {63 6f 6d 2e 65 78 61 6d 70 6c 65 2e 6e 65 77 6d 75 6c 74 69 68 64 66 63 61 6c 6c 72 64 73 6d 62 62 67 6e 6e 6d 6a 68 65 6c 6c 6f } //00 00 
	condition:
		any of ($a_*)
 
}