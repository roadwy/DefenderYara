
rule Trojan_Win32_Redline_NEBC_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 00 65 00 6c 00 6c 00 69 00 63 00 6f 00 73 00 69 00 74 00 79 00 20 00 61 00 72 00 64 00 6f 00 75 00 72 00 20 00 73 00 63 00 68 00 65 00 6d 00 61 00 74 00 69 00 63 00 } //02 00  Bellicosity ardour schematic
		$a_01_1 = {43 00 6f 00 75 00 72 00 73 00 65 00 73 00 20 00 63 00 6c 00 65 00 61 00 72 00 77 00 61 00 79 00 20 00 73 00 70 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 61 00 62 00 6c 00 65 00 20 00 79 00 69 00 65 00 6c 00 64 00 65 00 64 00 } //02 00  Courses clearway spending continuable yielded
		$a_01_2 = {42 00 65 00 65 00 70 00 73 00 20 00 6f 00 75 00 74 00 6c 00 61 00 77 00 69 00 6e 00 67 00 20 00 72 00 61 00 69 00 6e 00 69 00 6e 00 67 00 } //02 00  Beeps outlawing raining
		$a_01_3 = {46 00 6f 00 72 00 65 00 70 00 6c 00 61 00 79 00 } //02 00  Foreplay
		$a_01_4 = {56 00 65 00 6e 00 65 00 65 00 72 00 73 00 } //02 00  Veneers
		$a_01_5 = {76 00 70 00 61 00 6b 00 52 00 78 00 4b 00 6e 00 } //00 00  vpakRxKn
	condition:
		any of ($a_*)
 
}