
rule Trojan_Win32_VBKrypt_BB_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BB!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 41 53 54 52 4f 43 4f 4c 4f 54 4f 4d 59 53 } //1 GASTROCOLOTOMYS
		$a_01_1 = {53 79 73 73 69 74 61 66 6f 72 76 61 72 73 65 6c 65 74 70 69 70 69 } //1 Syssitaforvarseletpipi
		$a_01_2 = {46 72 61 61 64 65 73 66 69 64 75 73 6d 61 6c 65 72 69 65 72 73 63 61 31 } //1 Fraadesfidusmaleriersca1
		$a_01_3 = {53 61 63 72 61 6c 69 7a 61 74 69 6f 6e } //1 Sacralization
		$a_01_4 = {45 6c 65 63 74 72 6f 73 74 65 65 6c 35 } //1 Electrosteel5
		$a_01_5 = {54 65 6b 73 74 62 65 68 61 6e 64 6c 69 6e 67 73 73 79 73 74 65 6d 65 74 73 33 } //1 Tekstbehandlingssystemets3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}