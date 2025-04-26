
rule Trojan_BAT_ShellcodeRunner_HNAB_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.HNAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 11 6a 00 68 00 79 00 74 00 76 00 72 00 76 00 72 00 00 } //2
		$a_01_1 = {00 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //2
		$a_01_2 = {00 52 65 61 64 41 6c 6c 42 79 74 65 73 00 } //2 刀慥䅤汬祂整s
		$a_01_3 = {00 43 6f 70 79 00 } //1 䌀灯y
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}