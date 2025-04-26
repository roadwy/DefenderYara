
rule Trojan_Linux_Morcut_A_xp{
	meta:
		description = "Trojan:Linux/Morcut.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 6e 74 79 70 65 2e 73 72 63 } //1 vntype.src
		$a_01_1 = {56 49 51 52 20 31 2e 31 } //1 VIQR 1.1
		$a_01_2 = {55 73 61 67 65 3a 20 76 6e 38 74 6f 37 20 5b 2d 63 6f 6d 20 3c 63 3e 5d 20 5b 2d 6d } //1 Usage: vn8to7 [-com <c>] [-m
		$a_01_3 = {75 73 61 67 65 3a 20 2d 63 6f 6d 20 5b 63 68 61 72 } //1 usage: -com [char
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}