
rule Trojan_Win64_MagniSyscall_A{
	meta:
		description = "Trojan:Win64/MagniSyscall.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 33 c0 4c 8b d1 b8 18 00 00 00 0f 05 c3 e9 90 02 20 56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 90 01 04 48 8b e6 5e c3 90 00 } //01 00 
		$a_01_1 = {b9 fe 60 39 5b e8 } //01 00 
		$a_01_2 = {b9 3e 80 3c 9a e8 } //01 00 
		$a_03_3 = {e8 00 00 00 00 58 48 83 e8 05 48 2d 90 01 03 00 c3 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_MagniSyscall_A_2{
	meta:
		description = "Trojan:Win64/MagniSyscall.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b d1 b8 90 02 08 66 c7 90 01 02 0f 05 c6 90 01 02 c3 48 c7 90 01 02 0b 00 00 00 c7 90 02 04 10 00 00 e8 90 00 } //01 00 
		$a_03_1 = {b9 b5 6f 4d 32 e8 90 01 04 48 8b 4d 90 01 01 33 d2 ff d0 90 00 } //01 00 
		$a_01_2 = {b9 3e 80 3c 9a e8 } //01 00 
		$a_03_3 = {e8 00 00 00 00 58 48 83 e8 05 48 2d 90 01 03 00 c3 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}