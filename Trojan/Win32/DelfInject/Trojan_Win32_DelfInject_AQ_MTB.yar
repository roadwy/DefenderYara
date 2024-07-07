
rule Trojan_Win32_DelfInject_AQ_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //3 ShellExecuteA
		$a_01_1 = {5a 00 41 00 4d 00 4f 00 52 00 05 00 43 00 48 00 45 00 43 00 4d 00 05 00 42 00 42 00 4e 00 4b 00 4f } //3
		$a_81_2 = {4a 74 77 4e 73 77 56 78 73 57 74 65 4f 68 4a 35 4b 48 32 44 41 } //3 JtwNswVxsWteOhJ5KH2DA
		$a_81_3 = {44 69 6c 48 72 73 4c 79 75 4e } //3 DilHrsLyuN
		$a_81_4 = {48 65 6c 70 4b 65 79 77 6f 72 64 70 } //3 HelpKeywordp
		$a_81_5 = {41 75 74 6f 4c 69 6e 65 52 65 64 75 63 74 69 6f 6e } //3 AutoLineReduction
		$a_81_6 = {5c 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e 69 6e 69 } //3 \Configuration.ini
	condition:
		((#a_81_0  & 1)*3+(#a_01_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}