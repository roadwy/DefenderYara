
rule DDoS_Win32_MSNFlood_C{
	meta:
		description = "DDoS:Win32/MSNFlood.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 53 00 4e 00 20 00 53 00 70 00 61 00 6d 00 6d 00 65 00 72 00 } //01 00 
		$a_01_1 = {5c 73 79 73 74 33 32 2e 65 78 65 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 6e 2d 7a 79 73 63 2e 63 6f 6d 2f 73 68 61 6e 67 48 75 2f 50 53 59 2e 65 78 65 00 00 ff ff } //01 00 
		$a_01_3 = {2d 20 43 6f 6e 76 65 72 73 61 00 00 6c 6f 6c 6c 6c 6c 6c 20 68 74 74 70 3a 2f 2f } //00 00 
	condition:
		any of ($a_*)
 
}