
rule Trojan_Win32_Vundo_gen_BW{
	meta:
		description = "Trojan:Win32/Vundo.gen!BW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 50 ff 30 10 40 4f 75 f7 } //1
		$a_01_1 = {74 18 8a 14 38 30 14 31 40 83 f8 20 75 02 33 c0 41 3b 4c 24 04 75 eb } //1
		$a_01_2 = {83 7d e4 05 73 46 8b 45 e4 69 c0 08 02 00 00 05 } //1
		$a_01_3 = {49 6e 64 72 61 2e 64 6c 6c 00 61 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}