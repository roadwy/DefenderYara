
rule Trojan_O97M_Donoff_SR_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SR!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_02_1 = {3d 20 22 4d 73 68 74 61 [0-06] 3a 2f 2f 66 65 6a 61 6c 63 6f 6e 73 74 72 75 63 6f 65 73 2e 63 6f 6d 2e 62 72 2f 77 69 6e 64 6f 77 73 2e 74 78 74 } //1
		$a_00_2 = {53 68 65 6c 6c 20 28 56 61 72 29 } //1 Shell (Var)
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}