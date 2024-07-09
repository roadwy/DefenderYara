
rule TrojanDropper_Win32_Gernidru_gen_A{
	meta:
		description = "TrojanDropper:Win32/Gernidru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4e 49 47 45 52 53 48 45 4c 4c 33 32 2e 44 4c 4c 00 } //2
		$a_01_1 = {c0 4c 08 ff 04 } //1
		$a_01_2 = {80 74 01 ff 98 } //1
		$a_01_3 = {ff 74 24 04 ff 53 dc } //1
		$a_03_4 = {ff 53 e4 5e [0-10] ff 53 f4 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}