
rule PWS_Win32_Dentuti_A{
	meta:
		description = "PWS:Win32/Dentuti.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 83 31 19 40 66 83 3c 42 00 8d 0c 42 75 f1 } //1
		$a_01_1 = {80 74 04 10 5c 40 3b c6 7c f6 } //1
		$a_01_2 = {45 6e 64 20 77 69 74 68 20 73 74 61 74 75 73 3a 20 7b 30 78 25 58 7d 2c 20 74 68 49 64 3a 20 5b 25 64 5d } //1 End with status: {0x%X}, thId: [%d]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}