
rule Trojan_Win32_Bsymem_SQ_MTB{
	meta:
		description = "Trojan:Win32/Bsymem.SQ!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 63 6d 64 20 2f 63 20 63 6d 64 20 3c 20 43 6f 6c 70 6f 2e 73 6c 64 78 } //01 00  RunProgram="hidcon:cmd /c cmd < Colpo.sldx
		$a_01_1 = {41 00 76 00 72 00 61 00 2e 00 61 00 73 00 70 00 78 00 } //01 00  Avra.aspx
		$a_01_2 = {53 00 61 00 6c 00 75 00 74 00 61 00 2e 00 61 00 63 00 63 00 64 00 65 00 } //01 00  Saluta.accde
		$a_01_3 = {4d 00 65 00 7a 00 7a 00 6f 00 2e 00 61 00 63 00 63 00 64 00 72 00 } //00 00  Mezzo.accdr
	condition:
		any of ($a_*)
 
}