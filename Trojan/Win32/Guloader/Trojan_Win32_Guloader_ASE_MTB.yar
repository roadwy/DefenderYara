
rule Trojan_Win32_Guloader_ASE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {50 68 79 6c 6f 67 65 6e 65 74 69 63 61 6c 6c 79 2e 64 65 6c } //2 Phylogenetically.del
		$a_81_1 = {74 6f 6d 6d 65 6c 73 6b 72 75 65 72 6e 65 2e 61 66 73 } //1 tommelskruerne.afs
		$a_81_2 = {69 6e 64 64 61 74 61 66 75 6e 6b 74 69 6f 6e 65 6e 73 2e 54 72 61 } //1 inddatafunktionens.Tra
		$a_81_3 = {73 74 69 6c 68 65 64 65 72 6e 65 5c 74 61 6d 74 61 6d 6d 65 6e 73 2e 69 6e 69 } //1 stilhederne\tamtammens.ini
		$a_81_4 = {4b 6f 73 74 62 61 72 65 2e 74 65 73 } //1 Kostbare.tes
		$a_81_5 = {4f 76 65 72 68 61 6c 69 6e 67 36 34 5c 46 65 73 5c 73 71 75 61 6e 64 65 72 65 72 } //1 Overhaling64\Fes\squanderer
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}