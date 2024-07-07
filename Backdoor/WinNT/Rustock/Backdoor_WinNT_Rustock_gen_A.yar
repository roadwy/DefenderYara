
rule Backdoor_WinNT_Rustock_gen_A{
	meta:
		description = "Backdoor:WinNT/Rustock.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 38 50 e8 90 01 02 ff ff 8b 45 fc 68 90 01 04 83 c0 68 50 e8 90 01 02 ff ff 8b 75 fc 68 e0 90 90 b6 1c 90 00 } //1
		$a_01_1 = {c6 06 58 c6 46 01 68 89 76 02 c6 46 06 50 c6 46 07 68 c6 46 0c c3 } //1
		$a_01_2 = {68 b7 a4 7b 0f 6a 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}