
rule Trojan_AndroidOS_SmsThief_U{
	meta:
		description = "Trojan:AndroidOS/SmsThief.U,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 63 6f 76 65 72 2e 68 74 6d 6c 3f 64 49 44 3d } //02 00 
		$a_01_1 = {47 65 74 4d 6f 62 69 6c 65 44 6f 6d 61 69 6e } //02 00 
		$a_01_2 = {6a 73 61 6f 70 64 6a 70 61 73 64 6f 61 73 2e 6f 6e 6c 69 6e 65 2f } //00 00 
	condition:
		any of ($a_*)
 
}