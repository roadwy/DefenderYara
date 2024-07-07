
rule Trojan_O97M_Findropper_G{
	meta:
		description = "Trojan:O97M/Findropper.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 74 6f 6a 6c 6f 6d 6e 20 26 20 63 61 68 79 20 26 20 69 66 65 77 61 } //2 stojlomn & cahy & ifewa
		$a_02_1 = {3d 20 52 65 70 6c 61 63 65 28 55 73 65 72 46 6f 72 6d 31 2e 90 02 0a 2e 43 61 70 74 69 6f 6e 2c 20 22 23 22 2c 20 22 22 29 90 00 } //1
		$a_00_2 = {4d 73 67 42 6f 78 20 28 22 44 65 63 72 79 70 74 69 6f 6e 20 65 72 72 6f 72 22 29 } //1 MsgBox ("Decryption error")
		$a_02_3 = {4f 70 65 6e 20 90 02 0a 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 34 39 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}