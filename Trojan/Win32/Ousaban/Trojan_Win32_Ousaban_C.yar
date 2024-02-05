
rule Trojan_Win32_Ousaban_C{
	meta:
		description = "Trojan:Win32/Ousaban.C,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_81_1 = {23 4f 4e 2d 4c 49 4e 45 23 } //0a 00 
		$a_81_2 = {23 73 74 72 50 69 6e 67 4f 6b 23 } //0a 00 
		$a_81_3 = {23 78 79 53 63 72 65 65 23 } //0a 00 
		$a_81_4 = {23 73 74 72 49 6e 69 53 63 72 65 65 23 } //00 00 
		$a_00_5 = {5d 04 00 00 73 44 05 80 5c 25 00 00 74 44 05 80 00 00 01 00 08 00 0f 00 ac 21 4f 75 73 61 62 61 6e 2e 43 21 73 6d 73 00 } //00 01 
	condition:
		any of ($a_*)
 
}