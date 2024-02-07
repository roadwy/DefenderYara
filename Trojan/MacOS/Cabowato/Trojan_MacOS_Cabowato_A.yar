
rule Trojan_MacOS_Cabowato_A{
	meta:
		description = "Trojan:MacOS/Cabowato.A,SIGNATURE_TYPE_MACHOHSTR_EXT,1e 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 66 69 6c 65 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 61 6e 64 20 63 6f 6e 6e 6f 74 20 62 65 20 6f 70 65 6e 65 64 } //0a 00  This file is corrupted and connot be opened
		$a_01_1 = {3a 70 6f 73 20 6f 72 20 73 69 7a 65 20 65 72 72 6f 72 } //0a 00  :pos or size error
		$a_03_2 = {3d 00 05 00 00 90 02 06 3d 00 08 00 00 90 00 } //0a 00 
		$a_03_3 = {3d ff 03 00 00 90 02 06 3d 00 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}