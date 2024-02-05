
rule Trojan_Win32_Disstl_AQ_MTB{
	meta:
		description = "Trojan:Win32/Disstl.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4e 28 85 c9 7f 04 85 db 74 30 33 d2 8b c3 f7 75 0c 49 80 c2 30 89 4e 28 8b d8 80 fa 39 7e 11 80 7d 10 00 0f 94 c0 fe c8 24 e0 04 61 2c 3a 02 d0 8b 46 34 88 10 ff 4e 34 eb c5 } //01 00 
		$a_01_1 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 4d 65 6d 6f 72 79 } //01 00 
		$a_01_2 = {73 66 78 72 61 72 2e 65 78 65 } //01 00 
		$a_01_3 = {46 69 74 69 74 79 4e 75 6b 65 72 2d 76 31 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}