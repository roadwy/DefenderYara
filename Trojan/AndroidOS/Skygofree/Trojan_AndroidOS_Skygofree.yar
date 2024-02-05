
rule Trojan_AndroidOS_Skygofree{
	meta:
		description = "Trojan:AndroidOS/Skygofree,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {f0 b5 15 1c 4e 4e 0a 1c 6a 43 85 b0 7e 44 03 91 1c 1c 01 92 00 2a 01 d1 00 25 8e e0 } //01 00 
		$a_00_1 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 68 20 2d 63 } //01 00 
		$a_00_2 = {63 68 6d 6f 64 20 2d 52 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 77 68 61 74 73 61 70 70 } //01 00 
		$a_03_3 = {f0 b5 2d 4a 2d 4f 8b b0 7a 44 01 92 03 aa 7f 44 11 1c 70 cf 70 c1 3b 68 90 01 01 24 0b 60 90 01 01 28 48 d0 90 01 01 24 90 01 01 60 60 02 09 90 01 01 09 a9 08 aa 00 20 0a f0 90 01 02 0a f0 90 01 02 04 1c 42 1c 02 d0 00 28 06 d0 16 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}