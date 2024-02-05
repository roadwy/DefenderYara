
rule Trojan_AndroidOS_SmsSpy_O{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.O,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 61 74 73 6d 73 2e 70 68 70 3f 70 68 6f 6e 65 3d } //02 00 
		$a_01_1 = {65 72 72 6f 65 65 72 65 72 65 77 72 77 65 72 77 65 72 } //02 00 
		$a_01_2 = {73 69 71 65 2f 68 6f 6c 6f 2f 63 6f 6e 6e 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}