
rule Worm_Win32_Korgo_gen_B{
	meta:
		description = "Worm:Win32/Korgo.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 32 37 2e 30 2e 30 2e 31 3a 38 30 30 2f } //1 http://127.0.0.1:800/
		$a_01_1 = {61 76 73 65 72 76 65 32 2e 65 78 65 55 70 64 61 74 65 00 } //1
		$a_01_2 = {75 74 65 72 6d 31 33 2e 32 69 00 } //1
		$a_01_3 = {42 6f 74 20 4c 6f 61 64 65 72 } //1 Bot Loader
		$a_03_4 = {ff d6 8d 45 e8 33 ff 50 57 6a 01 ff 75 08 57 57 53 ff 55 ec 3b c7 74 ?? 50 ff d6 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=4
 
}