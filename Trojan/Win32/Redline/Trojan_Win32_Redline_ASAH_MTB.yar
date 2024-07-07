
rule Trojan_Win32_Redline_ASAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 69 6d 69 72 6f 68 69 73 61 78 69 6b 61 76 69 62 61 73 75 77 65 73 75 63 } //1 ximirohisaxikavibasuwesuc
		$a_01_1 = {6a 6f 6a 75 78 61 68 61 72 75 63 75 7a 6f 79 61 7a 75 68 6f 62 65 74 6f 20 6e 69 7a 61 77 61 78 61 67 65 66 61 77 61 79 61 67 65 76 6f 70 65 6b 65 6b 6f 7a 65 20 67 69 72 61 66 } //1 jojuxaharucuzoyazuhobeto nizawaxagefawayagevopekekoze giraf
		$a_01_2 = {78 69 6b 6f 74 75 7a 61 7a 69 6c 75 67 20 6c 6f 67 61 63 20 77 61 76 75 6b 65 6a 6f 64 75 6b 69 78 75 7a 65 79 65 6d 65 77 6f 63 6f 7a 6f 7a } //1 xikotuzazilug logac wavukejodukixuzeyemewocozoz
		$a_01_3 = {67 75 73 6f 6c 75 77 75 72 69 6a 65 6b 65 73 65 } //1 gusoluwurijekese
		$a_01_4 = {59 00 65 00 79 00 61 00 6b 00 65 00 74 00 20 00 74 00 61 00 66 00 65 00 62 00 6f 00 76 00 61 00 20 00 78 00 69 00 6d 00 6f 00 62 00 75 00 64 00 6f 00 72 00 61 00 67 00 61 00 63 00 } //1 Yeyaket tafebova ximobudoragac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}