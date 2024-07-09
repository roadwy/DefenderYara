
rule Trojan_O97M_Donota_B{
	meta:
		description = "Trojan:O97M/Donota.B,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 31 2e 41 6e 79 6b 65 79 } //1 Sheet1.Anykey
		$a_02_1 = {55 73 65 72 46 6f 72 6d [0-04] 2e 4c 61 62 65 6c 35 5f 43 6c 69 63 6b } //1
		$a_00_2 = {73 61 76 65 74 6f 66 69 6c 65 20 22 31 38 2e 65 22 20 26 20 22 78 65 22 2c 20 32 } //1 savetofile "18.e" & "xe", 2
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}