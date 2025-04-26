
rule Trojan_Win32_NSISInject_SVM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 72 79 74 68 72 6f 6d 61 6e 69 61 32 32 34 5c 73 61 6d 6d 65 6e 68 6f 62 6e 69 6e 67 65 72 6e 65 73 } //3 Erythromania224\sammenhobningernes
		$a_81_1 = {52 65 67 65 72 69 6e 67 65 72 6e 65 32 30 35 5c 70 72 69 6f 72 69 74 65 74 73 72 6b 6b 65 66 6c 67 65 6e 73 } //2 Regeringerne205\prioritetsrkkeflgens
		$a_81_2 = {41 72 61 62 65 73 6b 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 69 6d 70 65 61 63 68 5c 62 61 72 73 65 6c 73 6f 72 6c 6f 76 65 72 6e 65 } //2 Arabesks\Uninstall\impeach\barselsorloverne
		$a_81_3 = {48 61 6c 76 66 65 6d 73 65 72 5c 6c 75 66 74 73 70 72 69 6e 67 65 6e 65 73 } //1 Halvfemser\luftspringenes
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=8
 
}
rule Trojan_Win32_NSISInject_SVM_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.SVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_81_0 = {62 65 6e 69 61 6d 69 6e 6f 5c 55 6e 69 6e 73 74 61 6c 6c 5c 61 63 63 6f 72 64 65 64 5c 6a 75 6e 67 6c 69 65 72 } //2 beniamino\Uninstall\accorded\junglier
		$a_81_1 = {54 69 6c 73 79 6e 73 66 72 65 6e 64 65 73 2e 64 68 6f } //2 Tilsynsfrendes.dho
		$a_81_2 = {63 6f 65 78 65 72 74 5c 6b 72 65 64 73 65 2e 6d 65 74 } //2 coexert\kredse.met
		$a_81_3 = {54 72 69 76 65 6c 69 67 73 74 65 31 31 31 2e 66 61 67 } //2 Triveligste111.fag
		$a_81_4 = {71 75 6f 64 6c 69 62 65 74 61 72 69 61 6e 2e 69 6e 69 } //2 quodlibetarian.ini
		$a_81_5 = {66 6c 61 6d 6d 65 6b 61 73 74 65 72 65 6e 73 2e 69 6e 69 } //2 flammekasterens.ini
		$a_81_6 = {64 69 73 6c 75 73 74 65 72 65 64 2e 73 75 62 } //1 dislustered.sub
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1) >=13
 
}