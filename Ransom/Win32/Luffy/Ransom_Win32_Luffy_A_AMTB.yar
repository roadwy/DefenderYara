
rule Ransom_Win32_Luffy_A_AMTB{
	meta:
		description = "Ransom:Win32/Luffy.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {4c 75 66 66 79 2d 45 6e 63 2e 70 64 62 } //Luffy-Enc.pdb  1
		$a_80_1 = {31 33 33 37 5f 73 61 6c 74 21 } //1337_salt!  1
		$a_80_2 = {54 75 50 72 6f 79 65 63 74 6f 2e 69 6d 61 67 65 6e 2e 70 6e 67 } //TuProyecto.imagen.png  1
		$a_80_3 = {54 75 50 72 6f 79 65 63 74 6f 2e 64 72 6f 70 2e 65 78 65 } //TuProyecto.drop.exe  1
		$a_80_4 = {2e 6c 75 66 66 79 } //.luffy  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}