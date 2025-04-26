
rule Trojan_O97M_Donoff_SF_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SF!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {54 65 72 20 3d [0-24] 22 5c 55 73 65 72 73 2e } //1
		$a_00_1 = {50 72 69 6e 74 20 23 4e 74 6f 6f 6b 65 72 } //1 Print #Ntooker
		$a_00_2 = {43 6c 6f 73 65 20 23 4e 74 6f 6f 6b 65 72 } //1 Close #Ntooker
		$a_00_3 = {54 65 72 6f 6f 6b 6c 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 Terookl Application.StartupPath
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}