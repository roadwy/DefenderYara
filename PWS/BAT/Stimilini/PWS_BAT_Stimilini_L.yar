
rule PWS_BAT_Stimilini_L{
	meta:
		description = "PWS:BAT/Stimilini.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 54 45 41 4d 6c 4f 47 49 4e } //3 STEAMlOGIN
		$a_80_1 = {24 38 66 61 63 37 32 66 39 2d 31 30 36 35 2d 34 37 62 63 2d 62 33 35 30 2d 33 30 62 61 63 37 66 31 32 30 30 39 } //$8fac72f9-1065-47bc-b350-30bac7f12009  3
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*3) >=6
 
}