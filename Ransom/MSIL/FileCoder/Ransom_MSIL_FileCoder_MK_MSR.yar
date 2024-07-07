
rule Ransom_MSIL_FileCoder_MK_MSR{
	meta:
		description = "Ransom:MSIL/FileCoder.MK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {4f 6f 70 73 2c 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //Oops, your personal files have been encrypted!  2
		$a_80_1 = {64 65 73 63 72 69 70 74 69 6f 6e 2e 54 65 78 74 } //description.Text  2
		$a_80_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin delete shadows /all /quiet  2
		$a_80_3 = {6d 6f 64 69 66 79 2c 20 72 65 6e 61 6d 65 2c 20 64 65 6c 65 74 65 20 6f 72 20 63 68 61 6e 67 65 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 28 2e 64 73 65 63 29 20 66 69 6c 65 73 } //modify, rename, delete or change the encrypted (.dsec) files  2
		$a_80_4 = {59 6f 75 72 20 70 68 6f 74 6f 73 2c 20 6d 75 73 69 63 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 77 6f 72 6b 20 66 69 6c 65 73 2c 20 65 74 63 2e 20 61 72 65 20 6e 6f 77 20 65 6e 63 6f 64 65 64 20 61 6e 64 20 75 6e 72 65 61 64 61 62 6c 65 2e } //Your photos, music, documents, work files, etc. are now encoded and unreadable.  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=7
 
}