
rule Trojan_O97M_Obfuse_CT{
	meta:
		description = "Trojan:O97M/Obfuse.CT,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 61 6e 64 61 20 3d 20 22 64 76 66 65 72 74 33 36 74 67 65 34 74 67 66 22 } //01 00  Panda = "dvfert36tge4tgf"
		$a_01_1 = {4c 6f 61 64 69 6e 67 20 3d 20 22 64 76 66 65 72 74 33 36 74 67 65 34 74 67 66 22 } //00 00  Loading = "dvfert36tge4tgf"
	condition:
		any of ($a_*)
 
}