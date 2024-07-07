
rule Virus_Win32_Gael_gen_A{
	meta:
		description = "Virus:Win32/Gael.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {47 45 54 20 2f 76 78 39 2f 64 6c 2e 65 78 65 90 02 12 48 54 54 50 2f 31 2e 31 90 02 12 48 6f 73 74 3a 90 02 12 75 74 65 6e 74 69 2e 6c 79 63 6f 73 2e 69 74 90 00 } //1
		$a_01_1 = {68 69 63 75 6d 68 67 61 65 6c 54 52 52 ff d0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}