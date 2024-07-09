
rule HackTool_Linux_MimiPinguinC_A_{
	meta:
		description = "HackTool:Linux/MimiPinguinC.A!!MimiPinguinC.A,SIGNATURE_TYPE_ARHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 11 8f f0 ?? ?? ?? 0f 11 47 10 0f 11 47 30 0f 11 87 00 01 ?? ?? 0f 11 87 b0 01 } //10
		$a_03_1 = {48 89 87 a8 ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 89 97 a8 01 ?? ?? 66 0f 6f } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}