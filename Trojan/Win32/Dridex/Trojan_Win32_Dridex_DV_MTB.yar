
rule Trojan_Win32_Dridex_DV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {74 74 74 74 33 32 } //tttt32  03 00 
		$a_80_1 = {72 72 70 6f 6b 64 6d 67 6e 6e } //rrpokdmgnn  03 00 
		$a_80_2 = {46 6e 6c 6f 64 65 72 54 72 52 70 70 65 65 } //FnloderTrRppee  03 00 
		$a_80_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  03 00 
		$a_80_4 = {44 70 70 65 72 73 65 2e 70 64 62 } //Dpperse.pdb  03 00 
		$a_80_5 = {37 34 34 73 69 74 65 73 6c 57 33 43 2c } //744siteslW3C,  03 00 
		$a_80_6 = {41 64 62 6c 6f 63 6b 66 65 61 74 75 72 65 73 66 33 36 25 75 34 42 4b 41 } //Adblockfeaturesf36%u4BKA  00 00 
	condition:
		any of ($a_*)
 
}