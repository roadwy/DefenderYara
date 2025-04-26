
rule VirTool_Win32_VBInject_XD{
	meta:
		description = "VirTool:Win32/VBInject.XD,SIGNATURE_TYPE_PEHSTR,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 2e 52 2e 59 2e 50 2e 37 2e 33 2e 52 } //10 c.R.Y.P.7.3.R
		$a_01_1 = {28 00 50 00 55 00 54 00 41 00 54 00 41 00 4e 00 29 00 } //10 (PUTATAN)
		$a_01_2 = {73 74 72 75 70 20 65 6c 20 70 75 74 6f 20 61 6d 6f 20 78 44 44 44 44 44 } //1 strup el puto amo xDDDDD
		$a_01_3 = {44 65 6c 20 6d 61 71 75 69 6e 61 20 73 74 72 75 70 20 78 44 } //1 Del maquina strup xD
		$a_01_4 = {6d 61 6c 61 20 70 75 74 61 20 71 75 69 65 6e 20 6c 6f 20 6c 65 61 } //1 mala puta quien lo lea
		$a_01_5 = {6d 65 20 63 61 67 6f 20 65 6e 20 70 75 74 61 74 61 6e 20 64 69 67 6f 20 20 6d 61 74 61 74 61 6e 20 78 44 44 44 } //1 me cago en putatan digo  matatan xDDD
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}