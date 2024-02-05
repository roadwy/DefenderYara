
rule PWS_Win32_Banker_A{
	meta:
		description = "PWS:Win32/Banker.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 49 4d 45 } //01 00 
		$a_01_1 = {77 2e 31 36 33 2e 63 6f 6d 2e 7a 31 2e 72 71 62 61 6f 2e 63 6f 6d } //01 00 
		$a_01_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 51 00 51 00 4d 00 75 00 73 00 69 00 63 00 2e 00 65 00 78 00 65 00 } //02 00 
		$a_01_3 = {49 43 42 43 00 00 00 00 ff ff ff ff 03 00 00 00 43 4d 42 00 ff ff ff ff 03 00 00 00 43 43 42 00 ff ff ff ff 03 00 00 00 42 4f 43 } //00 00 
	condition:
		any of ($a_*)
 
}