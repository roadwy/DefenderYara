
rule Trojan_Win32_Killav_GI{
	meta:
		description = "Trojan:Win32/Killav.GI,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 70 76 61 } //1 exe.pva
		$a_01_1 = {65 78 65 2e 6e 72 6b 32 33 64 6f 6e } //1 exe.nrk23don
		$a_01_2 = {65 78 65 2e 64 6c 65 69 68 73 63 6d } //1 exe.dleihscm
		$a_01_3 = {65 78 65 2e 73 65 72 69 66 76 61 70 } //1 exe.serifvap
		$a_01_4 = {65 78 65 2e 70 70 61 63 63 } //1 exe.ppacc
		$a_01_5 = {65 78 65 2e 6e 6f 6d 74 6e 63 63 70 } //1 exe.nomtnccp
		$a_01_6 = {65 78 65 2e 32 33 6d 73 73 66 } //1 exe.23mssf
		$a_01_7 = {65 78 65 2e 74 72 61 74 73 76 61 6b } //1 exe.tratsvak
		$a_01_8 = {65 78 65 2e 65 63 69 76 72 65 73 66 70 6d } //1 exe.ecivresfpm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}