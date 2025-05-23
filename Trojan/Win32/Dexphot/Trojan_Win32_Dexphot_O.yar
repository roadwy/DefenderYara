
rule Trojan_Win32_Dexphot_O{
	meta:
		description = "Trojan:Win32/Dexphot.O,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_02_0 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 [0-20] 20 00 3d 00 20 00 27 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //10
		$a_02_1 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 [0-20] 20 00 2d 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 4c 00 69 00 73 00 74 00 20 00 27 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 } //10
		$a_00_2 = {73 00 75 00 70 00 65 00 72 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 31 00 37 00 30 00 39 00 2e 00 69 00 6e 00 66 00 6f 00 } //1 superdomain1709.info
		$a_00_3 = {67 00 75 00 61 00 72 00 64 00 6e 00 61 00 6d 00 65 00 2e 00 6e 00 65 00 74 00 } //1 guardname.net
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}