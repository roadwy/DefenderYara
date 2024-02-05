
rule Trojan_Win32_Qhost_CJ{
	meta:
		description = "Trojan:Win32/Qhost.CJ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 32 37 2e 30 2e 30 2e 31 20 77 77 77 2e 76 69 72 75 73 74 6f 74 61 6c 2e 63 6f 6d } //02 00 
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 76 69 72 75 73 73 63 61 6e 2e 6a 6f 74 74 69 2e 6f 72 67 } //02 00 
		$a_01_2 = {31 32 37 2e 30 2e 30 2e 31 20 66 6f 72 75 6d 73 2e 6d 61 6c 77 61 72 65 62 79 74 65 73 2e 6f 72 67 } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}