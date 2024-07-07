
rule Ransom_Win32_Sodinokibi_E{
	meta:
		description = "Ransom:Win32/Sodinokibi.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 51 41 41 41 47 30 35 53 57 34 41 41 41 41 41 37 36 77 57 6f } //1 KQAAAG05SW4AAAAA76wWo
		$a_00_1 = {6f 76 61 47 6f 67 41 41 41 41 41 41 41 41 41 41 } //1 ovaGogAAAAAAAAAA
		$a_00_2 = {69 6d 66 70 53 77 54 67 74 5a 58 31 35 6f 51 50 50 71 57 78 4d 65 6b 30 74 33 73 77 71 34 41 } //1 imfpSwTgtZX15oQPPqWxMek0t3swq4A
		$a_02_3 = {40 00 8b 44 8e 90 01 01 89 44 8f 90 01 01 8b 44 8e 90 01 01 89 44 8f 90 01 01 8b 44 8e 90 01 01 89 44 8f 90 01 01 8b 44 8e 90 01 01 89 44 8f 90 01 01 8b 44 8e 90 01 01 89 44 8f 90 01 01 8b 44 8e 90 01 01 89 44 8f 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}