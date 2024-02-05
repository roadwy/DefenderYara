
rule DDoS_Win32_Darktima_A{
	meta:
		description = "DDoS:Win32/Darktima.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 79 20 6e 61 6d 65 20 69 73 20 22 47 2d 42 6f 74 22 20 6f 72 20 22 47 42 6f 74 22 } //01 00 
		$a_01_1 = {4c 6e 4e 70 62 58 42 73 5a 57 68 30 64 48 42 6d 62 47 39 76 5a 41 3d 3d } //01 00 
		$a_01_2 = {4c 6e 42 76 63 33 52 6f 64 48 52 77 5a 6d 78 76 62 32 51 3d } //01 00 
		$a_01_3 = {5a 32 56 30 59 32 31 6b 4c 6e 42 6f 63 44 39 70 5a 44 30 3d } //00 00 
	condition:
		any of ($a_*)
 
}