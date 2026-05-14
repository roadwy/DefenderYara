
rule HackTool_Win32_Keygen_TNO_AMTB{
	meta:
		description = "HackTool:Win32/Keygen.TNO!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_80_0 = {54 4e 4f 20 43 6f 75 6e 63 69 6c } //TNO Council  2
		$a_80_1 = {74 6e 6f 2e 68 6f 6d 65 2e 6d 6c 2e 6f 72 67 } //tno.home.ml.org  2
		$a_80_2 = {54 68 65 20 4e 61 6d 65 6c 65 73 73 20 4f 6e 65 73 } //The Nameless Ones  2
		$a_80_3 = {4b 65 79 47 65 6e } //KeyGen  1
		$a_80_4 = {73 65 72 69 61 6c } //serial  1
		$a_80_5 = {63 72 61 63 6b 73 } //cracks  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=9
 
}