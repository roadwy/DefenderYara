
rule Trojan_Win32_Guloader_LWZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {55 6e 64 65 72 65 73 74 69 6d 61 74 65 73 2e 73 75 62 } //1 Underestimates.sub
		$a_81_1 = {64 69 6e 69 74 72 6f 70 68 65 6e 79 6c 68 79 64 72 61 7a 69 6e 65 2e 69 6e 64 } //1 dinitrophenylhydrazine.ind
		$a_81_2 = {6d 61 67 6e 65 74 6a 65 72 6e 73 74 65 6e 73 2e 74 78 74 } //1 magnetjernstens.txt
		$a_81_3 = {70 6c 61 64 73 68 6f 6c 64 65 72 66 65 6c 74 65 74 2e 61 75 72 } //1 pladsholderfeltet.aur
		$a_81_4 = {70 72 69 6e 74 70 72 6f 62 6c 65 6d 65 72 2e 72 6f 6e } //1 printproblemer.ron
		$a_81_5 = {75 6e 72 65 73 69 64 65 6e 74 69 61 6c 20 62 72 61 74 73 63 68 6e 67 6c 65 6e 73 } //1 unresidential bratschnglens
		$a_81_6 = {70 72 65 6c 6f 63 61 74 65 20 6e 61 70 68 74 68 61 6e 74 68 72 61 63 65 6e 65 } //1 prelocate naphthanthracene
		$a_81_7 = {72 61 67 65 64 65 20 61 65 72 6f 66 72 61 6d 65 73 } //1 ragede aeroframes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}