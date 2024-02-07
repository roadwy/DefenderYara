
rule Trojan_O97M_Obfuse_AX{
	meta:
		description = "Trojan:O97M/Obfuse.AX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 6b 78 6e 57 76 6d 28 29 } //01 00  Sub kxnWvm()
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //01 00  Call Shell(
		$a_01_2 = {6f 6d 72 61 6e 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 56 3a 4f 4e 2f 43 22 22 73 65 74 20 6c 57 3d 6f 2e 63 72 6d } //00 00  omran = "cmd.exe /V:ON/C""set lW=o.crm
	condition:
		any of ($a_*)
 
}