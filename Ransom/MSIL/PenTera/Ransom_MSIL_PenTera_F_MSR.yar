
rule Ransom_MSIL_PenTera_F_MSR{
	meta:
		description = "Ransom:MSIL/PenTera.F!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 4e 6f 74 65 2e 50 4e 54 2d 52 4e 53 4d } //RansomNote.PNT-RNSM  1
		$a_80_1 = {50 65 6e 74 65 72 57 61 72 65 2e 65 78 65 } //PenterWare.exe  1
		$a_80_2 = {52 61 6e 73 6f 6d 77 61 72 65 } //Ransomware  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}