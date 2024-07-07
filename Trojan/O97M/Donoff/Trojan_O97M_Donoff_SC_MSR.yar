
rule Trojan_O97M_Donoff_SC_MSR{
	meta:
		description = "Trojan:O97M/Donoff.SC!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 68 65 65 72 74 74 74 41 6f 62 2e 4f 70 65 6e } //1 sheertttAob.Open
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_00_2 = {3d 20 66 69 6c 65 32 73 61 76 72 73 61 76 65 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 22 } //1 = file2savrsave & Rnd & ".jse"
		$a_00_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //1 = Environ("USERPROFILE")
		$a_00_4 = {46 53 4f 5f 43 52 45 41 54 45 44 2e 57 72 69 74 65 20 6a 73 54 65 78 74 34 54 65 78 74 } //1 FSO_CREATED.Write jsText4Text
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}