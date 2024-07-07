
rule TrojanDropper_Win32_Surldoe_gen_A{
	meta:
		description = "TrojanDropper:Win32/Surldoe.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 a1 90 01 02 40 00 8b 00 ff d0 68 05 01 00 00 a1 90 01 02 40 00 50 a1 90 01 02 40 00 8b 00 ff d0 90 00 } //1
		$a_01_1 = {8b d7 8b 4d fc 02 54 19 ff 88 54 18 ff 43 4e 75 e7 } //1
		$a_03_2 = {8a 54 1a ff 80 ea 90 01 01 88 54 18 ff 43 4e 75 90 00 } //1
		$a_01_3 = {00 75 73 65 00 ff ff ff ff 02 00 00 00 72 33 00 } //1
		$a_00_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 65 00 78 00 65 00 6a 00 6f 00 69 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //-20 http://www.exejoiner.com
		$a_01_5 = {5c 5c 2e 5c 53 4d 41 52 54 56 53 44 } //-20 \\.\SMARTVSD
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*-20+(#a_01_5  & 1)*-20) >=3
 
}