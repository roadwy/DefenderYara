
rule Virus_Win32_Adept_gen_A{
	meta:
		description = "Virus:Win32/Adept.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 b8 7a d9 00 } //2
		$a_01_1 = {6a 02 68 70 ff ff ff } //1
		$a_01_2 = {f7 7d 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e6 } //2
		$a_01_3 = {53 68 65 6c 6c 42 6f 74 52 } //2 ShellBotR
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}