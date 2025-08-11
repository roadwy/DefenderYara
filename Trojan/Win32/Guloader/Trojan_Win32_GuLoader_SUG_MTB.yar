
rule Trojan_Win32_GuLoader_SUG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 70 61 72 6f 64 69 5c 6e 6f 6e 65 78 63 65 70 74 69 6f 6e 61 6c 6c 79 2e 6c 6e 6b } //1 \parodi\nonexceptionally.lnk
		$a_81_1 = {5c 56 65 6e 73 6b 61 62 73 62 79 65 72 6e 65 73 32 33 34 5c 62 72 65 61 74 68 73 2e 6a 70 67 } //1 \Venskabsbyernes234\breaths.jpg
		$a_81_2 = {47 6f 64 65 74 36 35 2e 67 79 74 } //1 Godet65.gyt
		$a_81_3 = {67 65 6e 67 6c 64 65 6c 73 65 72 73 2e 75 6e 66 } //1 gengldelsers.unf
		$a_81_4 = {6f 76 65 72 66 6f 72 73 69 6b 72 65 2e 6d 65 64 } //1 overforsikre.med
		$a_81_5 = {73 75 6d 6d 65 72 69 65 73 74 2e 61 70 70 } //1 summeriest.app
		$a_81_6 = {5c 73 75 72 63 68 61 72 67 65 73 2e 69 6e 69 } //1 \surcharges.ini
		$a_81_7 = {5c 53 6e 61 69 6c 65 72 79 5c 41 64 6d 69 6e 69 73 74 72 61 6e 74 2e 69 6e 69 } //1 \Snailery\Administrant.ini
		$a_81_8 = {5c 6b 6e 6c 65 64 65 6e 65 2e 69 6e 69 } //1 \knledene.ini
		$a_81_9 = {5c 61 62 6f 6c 69 74 69 6f 6e 69 73 65 64 5c 61 6e 74 69 65 6e 64 6f 77 6d 65 6e 74 2e 69 6e 69 } //1 \abolitionised\antiendowment.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}