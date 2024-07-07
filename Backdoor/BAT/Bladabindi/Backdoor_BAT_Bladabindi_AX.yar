
rule Backdoor_BAT_Bladabindi_AX{
	meta:
		description = "Backdoor:BAT/Bladabindi.AX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 6a 4c 6f 67 67 65 72 00 } //2
		$a_01_1 = {41 6e 74 69 54 61 73 6b 4d 61 6e 61 67 65 72 00 } //2 湁楴慔歳慍慮敧r
		$a_01_2 = {00 45 4e 42 00 44 45 42 00 } //1
		$a_01_3 = {00 44 4c 56 00 47 54 56 00 53 54 56 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}