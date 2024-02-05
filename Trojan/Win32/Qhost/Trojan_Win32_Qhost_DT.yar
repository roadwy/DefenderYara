
rule Trojan_Win32_Qhost_DT{
	meta:
		description = "Trojan:Win32/Qhost.DT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 32 37 2e 30 2e 30 2e 31 09 67 6f 6f 67 6c 65 2e 63 6f 6d 0d 0a 31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00 
		$a_00_1 = {25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 41 56 47 } //01 00 
		$a_00_2 = {69 70 63 6f 6e 66 69 67 20 2f 66 6c 75 73 68 64 6e 73 } //01 00 
		$a_01_3 = {33 d2 f7 75 08 83 fa 09 76 05 80 c2 57 eb 03 80 c2 30 } //00 00 
	condition:
		any of ($a_*)
 
}