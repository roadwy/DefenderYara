
rule Trojan_VBA_Runner_GPAX_MTB{
	meta:
		description = "Trojan:VBA/Runner.GPAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_81_0 = {52 75 6e 28 43 68 72 28 33 34 29 20 26 20 65 78 65 50 61 74 68 20 26 20 43 68 72 28 33 34 29 2c 20 31 2c 20 54 72 75 65 } //5 Run(Chr(34) & exePath & Chr(34), 1, True
		$a_81_1 = {6c 69 62 72 61 72 79 20 2f 6e 6f 6c 6f 67 6f 20 2f 75 6e 73 61 66 65 } //2 library /nologo /unsafe
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*2) >=7
 
}