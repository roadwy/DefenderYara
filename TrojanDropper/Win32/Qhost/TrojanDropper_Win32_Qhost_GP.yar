
rule TrojanDropper_Win32_Qhost_GP{
	meta:
		description = "TrojanDropper:Win32/Qhost.GP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_11_0 = {34 5c 6b 75 34 75 71 74 2e 6a 70 67 01 } //00 09 
		$a_30_1 = {5c 69 31 2e 65 78 65 01 00 0b 11 30 34 5c 74 65 73 } //74 2e 
		$a_61_2 = {01 00 08 11 30 31 5c 6f 6c 6f 6c 6f 00 00 5d 04 00 00 4c a0 02 80 5c 22 00 00 4d a0 02 80 00 00 01 00 1e 00 0c 00 d0 21 50 64 66 6a 73 63 2e 41 42 46 00 00 01 40 05 82 59 00 04 00 80 10 00 00 e0 b5 b6 ff 54 e3 e2 e4 76 c3 9f 1e 00 10 00 80 5d 04 00 00 4d a0 02 80 5c 27 00 00 4e a0 02 80 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}