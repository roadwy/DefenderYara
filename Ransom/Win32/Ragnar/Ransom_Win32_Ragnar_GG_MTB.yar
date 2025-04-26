
rule Ransom_Win32_Ragnar_GG_MTB{
	meta:
		description = "Ransom:Win32/Ragnar.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_80_0 = {2d 2d 2d 52 41 47 4e 41 52 20 53 45 43 52 45 54 2d 2d 2d } //---RAGNAR SECRET---  10
		$a_80_1 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  1
		$a_80_2 = {24 52 65 63 79 63 6c 65 2e 42 69 6e } //$Recycle.Bin  1
		$a_80_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //autorun.inf  1
		$a_80_4 = {62 6f 6f 74 73 65 63 74 2e 62 61 6b } //bootsect.bak  1
		$a_80_5 = {54 6f 72 20 62 72 6f 77 73 65 72 } //Tor browser  1
		$a_80_6 = {25 73 2d 25 73 2d 25 73 2d 25 73 2d 25 73 } //%s-%s-%s-%s-%s  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=14
 
}