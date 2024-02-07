
rule Trojan_AndroidOS_Piom_G{
	meta:
		description = "Trojan:AndroidOS/Piom.G,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 65 76 69 6c 74 68 72 65 61 64 73 } //01 00  com.evilthreads
		$a_01_1 = {63 6f 6d 2e 63 61 6e 64 72 6f 69 64 2e 62 6f 6f 74 6c 61 63 65 73 } //01 00  com.candroid.bootlaces
		$a_01_2 = {44 69 73 70 6c 61 79 73 20 6e 6f 74 69 66 69 63 61 74 69 6f 6e 73 20 66 6f 72 20 65 76 65 6e 74 73 20 72 65 67 61 72 64 69 6e 67 20 62 61 63 6b 67 72 6f 75 6e 64 20 77 6f 72 6b } //01 00  Displays notifications for events regarding background work
		$a_01_3 = {42 61 63 6b 67 72 6f 75 6e 64 20 50 72 6f 63 65 73 73 69 6e 67 } //00 00  Background Processing
	condition:
		any of ($a_*)
 
}