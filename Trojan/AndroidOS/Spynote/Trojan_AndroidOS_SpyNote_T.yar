
rule Trojan_AndroidOS_SpyNote_T{
	meta:
		description = "Trojan:AndroidOS/SpyNote.T,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 70 70 73 65 72 2e 76 65 72 61 70 70 } //01 00  com.appser.verapp
		$a_01_1 = {53 74 61 72 74 20 41 63 63 65 73 73 69 62 69 6c 69 74 79 } //01 00  Start Accessibility
		$a_01_2 = {47 6d 61 69 6c 3c 46 6f 72 67 65 74 2d 50 61 73 73 77 6f 72 64 3c 46 6f 72 67 65 74 2d 50 61 73 73 77 6f 72 64 } //01 00  Gmail<Forget-Password<Forget-Password
		$a_01_3 = {46 61 63 65 62 6f 6f 6b 3c 46 61 63 65 62 6f 6f 6b 20 4e 6f 74 20 69 6e 73 74 61 6c 6c 65 64 3c 46 61 63 65 62 6f 6f 6b 20 4e 6f 74 20 69 6e 73 74 61 6c 6c 65 64 } //00 00  Facebook<Facebook Not installed<Facebook Not installed
	condition:
		any of ($a_*)
 
}