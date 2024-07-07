
rule Worm_Win32_Gamarue_S{
	meta:
		description = "Worm:Win32/Gamarue.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a5 a5 a5 a5 33 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 50 ff 15 90 01 04 a3 90 01 04 83 f8 ff 74 1a 56 68 20 30 00 10 53 ff 35 18 30 00 10 50 ff 15 08 20 00 10 ff 15 18 30 00 10 90 00 } //1
		$a_00_1 = {65 78 70 6c 6f 72 65 00 64 00 65 00 73 00 6b 00 00 00 00 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}