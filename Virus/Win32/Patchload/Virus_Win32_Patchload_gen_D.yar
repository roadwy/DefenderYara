
rule Virus_Win32_Patchload_gen_D{
	meta:
		description = "Virus:Win32/Patchload.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 47 65 74 (50|00) } //1
		$a_00_1 = {b8 47 65 74 50 } //1
		$a_00_2 = {b8 72 6f 63 41 } //1
		$a_00_3 = {b8 4c 69 62 72 } //1
		$a_00_4 = {b8 4c 6f 61 64 } //1
		$a_00_5 = {b8 6f 6c 65 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}