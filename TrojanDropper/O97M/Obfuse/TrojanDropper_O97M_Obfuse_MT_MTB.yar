
rule TrojanDropper_O97M_Obfuse_MT_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.MT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 46 69 6c 65 41 28 22 43 3a 5c 4a 65 72 6f 70 69 74 5c 50 6f 74 65 72 69 2e 42 41 54 } //1 CreateFileA("C:\Jeropit\Poteri.BAT
		$a_03_1 = {48 74 79 75 5c 42 69 6f 70 65 72 5c 44 65 72 69 70 90 0a 16 00 43 3a 5c 90 00 } //1
		$a_00_2 = {53 65 74 20 64 6f 63 41 63 74 69 76 65 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 } //1 Set docActive = ActiveDocument
		$a_00_3 = {64 6f 63 4e 65 77 2e 41 63 74 69 76 61 74 65 } //1 docNew.Activate
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}