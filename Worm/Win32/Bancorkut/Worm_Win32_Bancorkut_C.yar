
rule Worm_Win32_Bancorkut_C{
	meta:
		description = "Worm:Win32/Bancorkut.C,SIGNATURE_TYPE_PEHSTR,19 00 19 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 73 65 72 76 69 63 65 6c 6f 67 69 6e 3f 63 6f 6e 74 69 6e 75 65 00 00 00 ff ff ff ff 21 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 6f 72 6b 75 74 2e 63 6f 6d 2e 62 72 2f 48 6f 6d 65 2e 61 73 70 78 } //0a 00 
		$a_01_1 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 73 65 72 76 69 63 65 6c 6f 67 69 6e 3f 73 65 72 76 69 63 65 3d 6f 72 6b 75 74 } //0a 00  www.google.com/accounts/servicelogin?service=orkut
		$a_01_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 00 00 00 00 ff ff ff ff 1b 00 00 00 50 61 67 69 6e 61 20 64 6f 20 6f 72 6b 75 74 20 66 6f 69 20 61 62 65 72 74 61 21 } //05 00 
		$a_01_3 = {45 6d 62 65 64 64 65 64 20 57 65 62 20 42 72 6f 77 73 65 72 20 66 72 6f 6d 3a 20 68 74 74 70 3a 2f 2f 62 73 61 6c 73 61 2e 63 6f 6d 2f } //00 00  Embedded Web Browser from: http://bsalsa.com/
	condition:
		any of ($a_*)
 
}