
rule Trojan_Win32_Guloader_AS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 76 65 72 6c 69 62 65 72 61 6c 69 7a 65 64 5c 67 61 65 73 74 66 72 69 5c 61 6e 74 69 67 6f 6e 6f 72 72 68 65 61 6c } //1 overliberalized\gaestfri\antigonorrheal
		$a_81_1 = {70 6c 61 73 74 72 65 5c 49 6e 74 65 72 65 73 73 65 73 61 6d 6d 65 6e 66 61 6c 64 65 74 73 2e 69 6e 69 } //1 plastre\Interessesammenfaldets.ini
		$a_81_2 = {76 73 65 6e 74 6c 69 67 68 65 64 73 6b 72 69 74 65 72 69 75 6d 2e 74 78 74 } //1 vsentlighedskriterium.txt
		$a_81_3 = {41 6e 74 69 6b 76 65 72 65 74 73 31 37 33 5c 44 65 6d 69 75 72 67 69 63 } //1 Antikverets173\Demiurgic
		$a_81_4 = {54 68 65 6f 70 68 69 6c 6f 73 6f 70 68 69 63 5c 63 68 69 72 72 75 70 69 6e 67 2e 69 6e 69 } //1 Theophilosophic\chirruping.ini
		$a_81_5 = {42 75 66 66 69 6e 67 5c 75 6e 65 78 70 6c 61 69 6e 65 64 2e 68 74 6d } //1 Buffing\unexplained.htm
		$a_81_6 = {75 6e 6c 75 62 72 69 63 61 74 69 76 65 2e 74 78 74 } //1 unlubricative.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}