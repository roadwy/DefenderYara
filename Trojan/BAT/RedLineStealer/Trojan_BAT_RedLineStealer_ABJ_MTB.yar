
rule Trojan_BAT_RedLineStealer_ABJ_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ABJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 72 59 00 00 70 72 65 00 00 70 28 22 00 00 0a 26 2a } //1
		$a_01_1 = {64 69 73 70 6f 73 69 6e 67 } //1 disposing
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_3 = {49 6e 69 74 69 61 6c 69 7a 65 43 6f 6d 70 6f 6e 65 6e 74 } //1 InitializeComponent
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}