
rule Trojan_BAT_FormBook_NMG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 61 35 31 64 36 32 31 2d 33 65 30 64 2d 34 32 39 33 2d 61 32 61 64 2d 39 36 34 37 32 31 62 66 66 66 37 62 } //2 2a51d621-3e0d-4293-a2ad-964721bfff7b
		$a_01_1 = {62 30 33 66 35 66 37 66 31 31 64 35 30 61 33 61 68 53 79 73 74 65 6d } //1 b03f5f7f11d50a3ahSystem
		$a_01_2 = {4f 6e 4b 65 79 44 6f 77 6e } //1 OnKeyDown
		$a_01_3 = {6b 65 79 45 76 65 6e 74 41 72 67 73 } //1 keyEventArgs
		$a_01_4 = {4e 6f 64 65 73 43 6f 6e 74 72 6f 6c 5f 4d 6f 75 73 65 4d 6f 76 65 } //1 NodesControl_MouseMove
		$a_01_5 = {61 64 64 5f 4d 6f 75 73 65 43 6c 69 63 6b } //1 add_MouseClick
		$a_01_6 = {4d 61 72 69 75 73 7a 20 4b 6f 6d 6f 72 6f 77 73 6b 69 } //1 Mariusz Komorowski
		$a_01_7 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 23 53 79 73 74 65 6d } //1 b77a5c561934e089#System
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}