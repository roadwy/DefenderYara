
rule HackTool_Linux_Spectre_A{
	meta:
		description = "HackTool:Linux/Spectre.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {3d 3d 3d 3d 3d 3d 3d 20 4d 65 6d 6f 72 79 20 6d 61 70 3a 20 3d 3d 3d 3d 3d 3d 3d 3d } //======= Memory map: ========  1
		$a_80_1 = {3d 3d 3d 3d 3d 3d 3d 20 42 61 63 6b 74 72 61 63 65 3a 20 3d 3d 3d 3d 3d 3d 3d 3d 3d } //======= Backtrace: =========  1
		$a_80_2 = {54 45 53 54 20 54 45 53 54 20 54 45 53 54 } //TEST TEST TEST  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}