
rule Worm_Win32_Autorun_PA{
	meta:
		description = "Worm:Win32/Autorun.PA,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 10 6a 01 6a 00 6a 05 68 86 00 00 00 6a 00 6a 00 6a 00 68 84 03 00 00 6a 00 6a 00 6a 00 6a 1e ff 15 } //5
		$a_01_1 = {49 6e 20 4d 65 6d 6f 72 79 20 4f 66 20 43 38 43 00 } //1
		$a_01_2 = {bd f6 d2 d4 b4 cb b5 bf c4 ee b1 c8 bc e7 21 00 } //1
		$a_01_3 = {ce f7 c4 cf c3 f1 d7 e5 b4 f3 d1 a7 d4 f8 be ad b5 c4 42 42 53 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}