
rule Trojan_Win32_GuLoader_RBM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 61 6c 6c 69 74 79 70 65 64 20 61 77 61 72 75 69 74 65 20 6d 65 73 72 6f 70 69 61 6e } //1 callityped awaruite mesropian
		$a_81_1 = {75 6e 64 65 72 73 61 74 75 72 61 74 69 6f 6e 20 6e 75 6d 62 65 72 6f 75 73 } //1 undersaturation numberous
		$a_81_2 = {72 61 61 76 61 72 65 70 72 69 73 } //1 raavarepris
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_GuLoader_RBM_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 70 6c 61 6e 75 6c 61 72 5c 75 6e 64 65 72 76 69 73 6e 69 6e 67 73 6f 6d 72 61 61 64 65 74 73 } //1 \planular\undervisningsomraadets
		$a_81_1 = {5c 46 65 72 6d 65 6e 74 65 72 65 74 31 35 36 5c 6f 63 63 6c 75 73 6f 63 65 72 76 69 63 61 6c } //1 \Fermenteret156\occlusocervical
		$a_81_2 = {68 6f 6e 6f 72 65 72 65 64 65 73 2e 61 75 74 } //1 honoreredes.aut
		$a_81_3 = {5c 43 61 74 68 79 5c 2a 2e 62 69 6e } //1 \Cathy\*.bin
		$a_81_4 = {25 6d 75 67 67 65 72 79 25 5c 4f 78 79 67 65 6e 73 5c 46 6c 65 74 66 69 6c 65 6e } //1 %muggery%\Oxygens\Fletfilen
		$a_81_5 = {5c 65 6e 65 76 72 65 6c 73 65 72 2e 69 6e 69 } //1 \enevrelser.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=4
 
}