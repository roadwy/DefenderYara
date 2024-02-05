
rule Trojan_Win32_PhantomStar_C_dha{
	meta:
		description = "Trojan:Win32/PhantomStar.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 73 79 73 74 65 6d 20 70 72 4f 63 65 53 73 5d } //01 00 
		$a_01_1 = {72 75 6e 44 4c 6c 33 32 2e 45 78 65 } //01 00 
		$a_01_2 = {4d 70 63 6d 64 72 75 6e 2e 65 58 65 } //01 00 
		$a_01_3 = {77 6d 70 6e 45 54 77 6b 2e 65 78 45 } //01 00 
		$a_01_4 = {4a 61 76 61 46 58 50 61 63 6b 61 67 65 72 4d 75 74 61 6e 74 } //01 00 
		$a_02_5 = {2d eb 4a 00 00 50 ff 15 90 09 06 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}