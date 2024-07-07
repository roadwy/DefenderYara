
rule TrojanClicker_Win32_Wesurf_gen_A{
	meta:
		description = "TrojanClicker:Win32/Wesurf.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 6c 6c 6c 73 73 73 2e 69 6e 66 6f 2f 67 69 72 6c 2e 68 74 6d 6c 00 00 00 49 45 58 50 4c 4f 52 45 2e 45 58 45 00 } //1
		$a_03_1 = {6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 6a 00 e8 90 00 } //1
		$a_03_2 = {68 a8 61 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 e8 03 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 e8 03 00 00 90 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*5) >=7
 
}