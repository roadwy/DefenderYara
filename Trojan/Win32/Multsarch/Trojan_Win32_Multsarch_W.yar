
rule Trojan_Win32_Multsarch_W{
	meta:
		description = "Trojan:Win32/Multsarch.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_11_0 = {4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 a0 00 07 40 00 1a 00 00 00 fb 10 6a 72 01 } //00 36 
		$a_83_1 = {20 0f b7 c0 83 c6 02 66 3b c2 75 90 14 0f b7 46 fe 8d 50 } //be 66 
		$a_fa_2 = {77 03 83 c0 20 0f b7 c8 0f b7 07 8d 50 be 66 83 fa 17 77 03 83 c0 20 0f b7 c0 90 00 00 00 5d 04 00 00 a2 03 03 80 5c 23 00 00 a3 03 03 80 00 00 01 00 08 00 0d 00 ac 21 4d 75 6c 74 73 61 72 63 68 2e 52 00 00 01 40 05 82 70 00 04 00 78 ed 01 00 29 00 29 00 06 00 00 01 00 23 01 66 66 32 2e 76 62 73 00 fe 25 25 5c 77 73 63 72 69 70 74 2e 65 78 65 20 fd 99 80 5c 66 66 32 2e 76 62 73 01 00 2d 01 } //66 69 
	condition:
		any of ($a_*)
 
}