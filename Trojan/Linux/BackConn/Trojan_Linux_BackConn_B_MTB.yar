
rule Trojan_Linux_BackConn_B_MTB{
	meta:
		description = "Trojan:Linux/BackConn.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 69 6e 69 74 2e 64 2f 75 70 64 61 74 65 2d 6e 6f 74 69 66 69 65 72 } //01 00 
		$a_00_1 = {65 74 63 2f 72 63 32 2e 64 2f 53 30 31 75 70 64 61 74 65 2d 6e 6f 74 69 66 69 65 72 } //02 00 
		$a_01_2 = {48 be 58 2d 41 63 63 65 73 73 43 c6 44 37 10 00 48 89 32 48 8b 34 24 f2 ae 48 8d 42 0a 48 89 c7 48 f7 d1 48 ff c9 f3 a4 c6 44 1a 0a 00 48 8b 4c 24 28 48 8d 5c 24 38 48 8d 74 24 58 49 89 d8 ba 02 00 00 00 0f 11 5c 24 38 48 8d 3d aa 43 13 00 0f 11 5c 24 48 e8 95 fb ff ff 85 c0 0f 84 e7 fe ff ff 48 83 7c 24 40 00 75 07 } //00 00 
	condition:
		any of ($a_*)
 
}