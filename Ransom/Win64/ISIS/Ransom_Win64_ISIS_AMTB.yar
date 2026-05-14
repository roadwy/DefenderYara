
rule Ransom_Win64_ISIS_AMTB{
	meta:
		description = "Ransom:Win64/ISIS!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {49 53 49 53 52 61 6e 73 6f 6d 2e 70 64 62 } //ISISRansom.pdb  1
		$a_80_1 = {49 53 49 53 5f 52 41 4e 53 4f 4d 5f 4e 4f 54 45 2e 74 78 74 } //ISIS_RANSOM_NOTE.txt  1
		$a_80_2 = {69 73 69 73 5f 77 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //isis_wallpaper.bmp  1
		$a_80_3 = {49 53 49 53 20 52 41 4e 53 4f 4d 57 41 52 45 } //ISIS RANSOMWARE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}