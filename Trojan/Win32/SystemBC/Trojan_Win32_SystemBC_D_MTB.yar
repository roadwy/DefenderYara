
rule Trojan_Win32_SystemBC_D_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.D!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 c0 19 73 1e 00 05 43 55 fb 3c c1 d8 10 03 c1 85 d2 } //01 00 
		$a_01_1 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 65 70 20 62 79 70 61 73 73 20 2d 66 69 6c 65 } //01 00 
		$a_01_2 = {4c 64 72 4c 6f 61 64 44 6c 6c } //01 00 
		$a_01_3 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}