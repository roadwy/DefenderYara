
rule Trojan_PowerShell_PsAttack_R{
	meta:
		description = "Trojan:PowerShell/PsAttack.R,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00 } //10 amsiutils
		$a_00_1 = {61 00 6d 00 73 00 69 00 69 00 6e 00 69 00 74 00 66 00 61 00 69 00 6c 00 65 00 64 00 } //10 amsiinitfailed
		$a_00_2 = {67 00 65 00 74 00 66 00 69 00 65 00 6c 00 64 00 } //1 getfield
		$a_00_3 = {6e 00 6f 00 6e 00 70 00 75 00 62 00 6c 00 69 00 63 00 2c 00 73 00 74 00 61 00 74 00 69 00 63 00 } //1 nonpublic,static
		$a_00_4 = {73 00 65 00 74 00 76 00 61 00 6c 00 75 00 65 00 } //1 setvalue
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=11
 
}