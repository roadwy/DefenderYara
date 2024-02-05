
rule Trojan_WinNT_Adwind_YG_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YG!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {7b 6f 6b 68 7f 69 7c 68 33 } //01 00 
		$a_00_1 = {73 61 70 60 77 61 74 60 6a 61 69 75 6c 74 6d 60 65 63 33 } //01 00 
		$a_00_2 = {7e 68 7f 7e 6d 7d 79 69 74 7f 62 7c 65 7f 33 } //01 00 
		$a_00_3 = {54 42 42 54 47 40 53 43 49 40 5f 61 6d 63 6e 43 44 42 } //01 00 
		$a_00_4 = {7c 6c 7f 6d 69 7d 7b 6d 68 21 2a 20 2d 7d 6f 7c 76 61 6f 66 74 7d 77 3c } //00 00 
	condition:
		any of ($a_*)
 
}