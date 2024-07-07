
rule Virus_Win32_Frayemet_gen_A{
	meta:
		description = "Virus:Win32/Frayemet.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4d 79 46 69 6c 65 28 40 6d 79 5f 61 72 72 61 79 2c 73 69 7a 65 6f 66 28 6d 79 5f 61 72 72 61 79 29 2c 27 7e 2e 65 78 65 27 29 3b 0d 0a 00 7b 24 49 46 44 45 46 20 4d 53 57 49 4e 44 4f 57 53 7d 0d 0a 70 72 6f 63 65 64 75 72 65 20 5f 49 6e 69 74 45 78 65 } //1
		$a_01_1 = {53 00 79 00 73 00 49 00 6e 00 69 00 74 00 2e 00 70 00 61 00 73 00 } //1 SysInit.pas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}