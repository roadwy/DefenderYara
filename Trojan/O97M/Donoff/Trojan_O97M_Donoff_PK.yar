
rule Trojan_O97M_Donoff_PK{
	meta:
		description = "Trojan:O97M/Donoff.PK,SIGNATURE_TYPE_MACROHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_00_0 = {54 45 4d 50 24 } //1 TEMP$
		$a_00_1 = {5c 72 65 73 75 6d 65 2e 68 74 61 } //10 \resume.hta
		$a_00_2 = {41 44 4f 44 42 2e 53 74 72 65 61 6d 24 } //1 ADODB.Stream$
		$a_02_3 = {68 74 74 70 73 3a 2f 2f 62 75 69 6c 64 2d 6d 79 2d 72 65 73 75 6d 65 2e 63 6f 6d 2f 90 02 33 2e 68 74 61 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10) >=22
 
}