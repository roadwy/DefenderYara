
rule Trojan_BAT_XWorm_PGO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 61 74 6c 6f 61 64 65 72 2e 65 78 65 } //5 ratloader.exe
		$a_01_1 = {6f 4c 66 70 6b 68 44 4c 78 4d 41 50 41 68 6a 32 6e 50 4f 41 37 77 54 55 77 44 4c 68 6b 47 64 39 4f 32 51 4b 30 } //5 oLfpkhDLxMAPAhj2nPOA7wTUwDLhkGd9O2QK0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}