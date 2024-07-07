
rule Worm_Win32_MyDoom_EM_MTB{
	meta:
		description = "Worm:Win32/MyDoom.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {64 65 76 69 6c 32 31 30 30 } //1 devil2100
		$a_01_1 = {73 68 61 69 62 32 30 30 } //1 shaib200
		$a_01_2 = {61 6c 6d 61 37 72 6f 6f 6d 6d } //1 alma7roomm
		$a_01_3 = {6a 61 73 69 6d 38 31 30 } //1 jasim810
		$a_01_4 = {77 61 72 72 65 72 5f 35 30 } //1 warrer_50
		$a_01_5 = {6d 6f 68 61 6d 6d 65 64 30 30 37 } //1 mohammed007
		$a_01_6 = {72 61 68 2e 70 6f 6c 61 6b 61 } //1 rah.polaka
		$a_01_7 = {73 73 6b 65 72 61 6c 65 78 61 6e 64 65 72 } //1 sskeralexander
		$a_01_8 = {61 6d 62 61 74 75 6b 61 6d } //1 ambatukam
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}