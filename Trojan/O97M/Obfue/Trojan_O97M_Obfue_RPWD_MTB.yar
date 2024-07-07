
rule Trojan_O97M_Obfue_RPWD_MTB{
	meta:
		description = "Trojan:O97M/Obfue.RPWD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 29 2e 45 78 65 63 20 22 50 6f 77 65 22 20 2b 20 67 6d 32 20 2b 20 67 6d 33 20 2b 20 67 6d 34 } //1 ().Exec "Powe" + gm2 + gm3 + gm4
		$a_03_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 07 29 90 00 } //1
		$a_01_2 = {78 4f 75 74 20 3d 20 78 4f 75 74 20 26 20 56 42 41 2e 4d 69 64 28 78 56 61 6c 75 65 2c 20 69 2c 20 31 29 } //1 xOut = xOut & VBA.Mid(xValue, i, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}