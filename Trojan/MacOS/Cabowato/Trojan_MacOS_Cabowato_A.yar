
rule Trojan_MacOS_Cabowato_A{
	meta:
		description = "Trojan:MacOS/Cabowato.A,SIGNATURE_TYPE_MACHOHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 66 69 6c 65 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 61 6e 64 20 63 6f 6e 6e 6f 74 20 62 65 20 6f 70 65 6e 65 64 } //10 This file is corrupted and connot be opened
		$a_01_1 = {3a 70 6f 73 20 6f 72 20 73 69 7a 65 20 65 72 72 6f 72 } //10 :pos or size error
		$a_03_2 = {3d 00 05 00 00 [0-06] 3d 00 08 00 00 } //10
		$a_03_3 = {3d ff 03 00 00 [0-06] 3d 00 03 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10) >=30
 
}