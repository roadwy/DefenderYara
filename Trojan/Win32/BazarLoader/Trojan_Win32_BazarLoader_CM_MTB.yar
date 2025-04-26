
rule Trojan_Win32_BazarLoader_CM_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 43 6f 75 6c 64 } //3 AllCould
		$a_81_1 = {45 70 72 6f 79 41 6b 6c 57 } //3 EproyAklW
		$a_81_2 = {47 72 65 61 74 54 69 6d 65 } //3 GreatTime
		$a_81_3 = {6b 6e 6e 74 61 67 73 74 70 76 6e 77 61 } //3 knntagstpvnwa
		$a_81_4 = {66 78 61 6f 77 6b 68 6b 6e 6e 74 61 67 73 75 70 } //3 fxaowkhknntagsup
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}