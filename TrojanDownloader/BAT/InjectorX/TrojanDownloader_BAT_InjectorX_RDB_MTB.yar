
rule TrojanDownloader_BAT_InjectorX_RDB_MTB{
	meta:
		description = "TrojanDownloader:BAT/InjectorX.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 64 71 76 6d 76 63 } //1 Rdqvmvc
		$a_01_1 = {52 76 77 62 65 65 6e 6d 6e 73 77 73 6d 69 68 68 6a 75 62 67 } //1 Rvwbeenmnswsmihhjubg
		$a_01_2 = {51 68 6e 78 61 68 68 69 75 63 76 69 79 72 67 78 63 72 71 70 65 77 74 6a } //1 Qhnxahhiucviyrgxcrqpewtj
		$a_01_3 = {64 32 34 38 35 65 36 32 34 30 30 65 34 39 32 30 35 66 32 38 36 35 37 34 38 38 39 63 65 34 62 31 } //1 d2485e62400e49205f286574889ce4b1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}