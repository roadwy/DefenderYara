
rule Trojan_Win32_Dridex_RQIJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RQIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {62 62 6d 65 65 6f 6d 6e 76 70 6f 70 2e 64 6c 6c } //1 bbmeeomnvpop.dll
		$a_01_1 = {52 46 46 47 54 45 51 2e 70 64 62 } //1 RFFGTEQ.pdb
		$a_01_2 = {42 6c 6f 63 6b 49 6e 70 75 74 } //1 BlockInput
		$a_01_3 = {74 6f 62 69 74 65 67 61 74 65 2e 32 30 35 61 6e 64 74 61 75 6c 73 6f 6d 65 77 68 61 74 4c } //1 tobitegate.205andtaulsomewhatL
		$a_01_4 = {62 7a 31 38 35 31 6d 6f 6e 62 63 61 62 63 6f 72 65 73 70 75 62 73 79 65 70 43 68 62 6f 62 69 75 6d 36 } //1 bz1851monbcabcorespubsyepChbobium6
		$a_01_5 = {74 68 61 74 6d 6f 64 65 6e 73 65 72 31 61 72 65 42 } //1 thatmodenser1areB
		$a_01_6 = {70 72 65 76 62 6f 75 73 4d 6e 75 70 70 6f 72 74 61 75 74 6f 2d 75 70 62 62 74 69 6e 67 } //1 prevbousMnupportauto-upbbting
		$a_01_7 = {52 62 72 65 62 65 61 62 65 64 74 62 65 79 70 6f 69 6e 74 73 2e 36 62 49 6e 31 35 33 34 35 36 37 38 4b 6c } //1 Rbrebeabedtbeypoints.6bIn15345678Kl
		$a_01_8 = {42 70 6f 64 6d 73 73 65 6c 69 6f 63 44 66 72 74 6f 6f } //1 BpodmsseliocDfrtoo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}