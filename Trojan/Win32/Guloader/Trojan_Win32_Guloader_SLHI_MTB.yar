
rule Trojan_Win32_Guloader_SLHI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 72 65 64 6e 69 6e 67 73 6d 65 74 65 6f 72 6f 6c 6f 67 69 73 6b 65 36 } //2 Spredningsmeteorologiske6
		$a_01_1 = {4b 6f 64 6e 69 6e 67 73 74 65 6f 72 69 65 6e } //2 Kodningsteorien
		$a_01_2 = {50 61 72 74 69 6b 75 6c 61 72 69 73 6d 65 6e 35 } //2 Partikularismen5
		$a_01_3 = {54 72 79 6c 6c 65 6b 75 6e 73 74 6e 65 72 65 6e 33 } //2 Tryllekunstneren3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}