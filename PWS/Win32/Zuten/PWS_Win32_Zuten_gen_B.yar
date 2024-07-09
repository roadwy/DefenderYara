
rule PWS_Win32_Zuten_gen_B{
	meta:
		description = "PWS:Win32/Zuten.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 6a 40 6a 01 56 ff 15 ?? ?? 00 10 8b 45 08 c6 06 e9 2b c6 6a 01 83 e8 05 89 46 01 } //1
		$a_01_1 = {5f 4c 69 75 4d 61 7a 69 00 } //1
		$a_01_2 = {4a 75 6d 70 48 6f 6f 6b 4f 66 66 00 4a 75 6d 70 48 6f 6f 6b 4f 6e 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}