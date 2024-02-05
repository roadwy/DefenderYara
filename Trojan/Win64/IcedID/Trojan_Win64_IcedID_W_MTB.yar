
rule Trojan_Win64_IcedID_W_MTB{
	meta:
		description = "Trojan:Win64/IcedID.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 83 f9 0a 0f 9c c0 30 c8 41 ba c4 06 30 fe b8 ae 9b b9 14 41 0f 45 c2 44 39 c2 0f 94 44 24 06 41 b8 ae 9b b9 14 44 0f 45 d0 41 83 f9 0a 0f 9c 44 24 07 44 0f 4d d0 b8 ed 48 41 d8 41 b9 1b 6d 49 41 } //03 00 
		$a_80_1 = {61 68 74 7a 6d 6a 6c 73 6c 6f 6a 77 6d } //ahtzmjlslojwm  03 00 
		$a_80_2 = {61 73 64 78 6f 76 67 68 77 7a 68 66 } //asdxovghwzhf  03 00 
		$a_80_3 = {62 6e 7a 79 71 64 69 6e 63 66 69 } //bnzyqdincfi  03 00 
		$a_80_4 = {63 68 62 65 71 75 73 6f 68 6d 79 6e } //chbequsohmyn  00 00 
	condition:
		any of ($a_*)
 
}