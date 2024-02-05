
rule Trojan_BAT_Sistomerdly_A{
	meta:
		description = "Trojan:BAT/Sistomerdly.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 69 74 44 65 73 74 72 75 63 74 69 6f 6e 00 69 6e 69 74 42 6f 6d 62 } //01 00 
		$a_01_1 = {64 65 73 74 72 6f 79 46 69 6c 65 53 79 73 74 65 6d 00 64 65 73 74 72 6f 79 50 72 6f 66 69 6c 65 73 00 64 65 73 74 72 6f 79 50 72 6f 67 72 61 6d 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}