
rule Trojan_AndroidOS_Brazking_A{
	meta:
		description = "Trojan:AndroidOS/Brazking.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 65 72 74 69 66 69 63 61 74 65 20 63 68 61 69 6e 20 74 6f 6f 20 6c 6f 6e 67 } //2 Certificate chain too long
		$a_00_1 = {41 63 65 73 73 69 62 69 6c 69 64 61 64 65 } //2 Acessibilidade
		$a_00_2 = {64 75 6d 70 61 40 } //2 dumpa@
		$a_00_3 = {70 65 72 66 6f 72 6d 47 6c 6f 62 61 6c 41 63 74 69 6f 6e } //2 performGlobalAction
		$a_00_4 = {46 45 43 48 41 5f 54 52 41 56 41 } //2 FECHA_TRAVA
		$a_00_5 = {40 66 65 63 68 61 3f 6b 65 79 3d } //2 @fecha?key=
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=10
 
}