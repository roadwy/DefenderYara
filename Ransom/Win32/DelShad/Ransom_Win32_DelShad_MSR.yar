
rule Ransom_Win32_DelShad_MSR{
	meta:
		description = "Ransom:Win32/DelShad!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //Delete Shadows /All /Quiet  2
		$a_80_1 = {73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //shadowcopy delete  2
		$a_80_2 = {64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 20 71 75 69 65 74 } //delete catalog - quiet  2
		$a_80_3 = {68 6f 77 20 74 6f 20 72 65 63 6f 76 65 72 2e 74 78 74 } //how to recover.txt  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=7
 
}