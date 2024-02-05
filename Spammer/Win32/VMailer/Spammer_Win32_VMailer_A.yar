
rule Spammer_Win32_VMailer_A{
	meta:
		description = "Spammer:Win32/VMailer.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 52 65 6c 65 61 73 65 5c 6d 61 69 6c 65 72 6d 6f 64 75 6c 65 31 39 39 2e 70 64 62 } //01 00 
		$a_01_1 = {2d 2d 2d 20 42 61 74 63 68 20 6f 66 20 25 64 20 66 6f 72 20 64 6f 6d 61 69 6e 20 25 73 } //01 00 
		$a_01_2 = {73 65 6e 74 6d 61 69 6c 73 20 73 65 72 76 65 72 3d 25 73 3a 25 64 20 6c 69 73 74 69 64 3d 25 75 20 70 69 64 3d 25 75 } //00 00 
	condition:
		any of ($a_*)
 
}