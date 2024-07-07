
rule PWS_Win32_Banker_L{
	meta:
		description = "PWS:Win32/Banker.L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b f0 8b d3 8b c6 8b 08 ff 51 08 c6 46 3f 28 } //3
		$a_01_1 = {69 6d 67 62 74 6e 43 6c 69 63 6b } //1 imgbtnClick
		$a_01_2 = {77 69 6e 64 6f 77 73 5c 74 65 6d 70 2e 6a 70 67 } //1 windows\temp.jpg
		$a_01_3 = {55 53 45 52 20 25 73 40 25 73 40 25 73 } //1 USER %s@%s@%s
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}