
rule Virus_Win32_Alvabrig_gen_C{
	meta:
		description = "Virus:Win32/Alvabrig.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8d 40 7c 8b 40 3c 95 e8 00 00 00 00 5e 90 } //1
		$a_01_1 = {ff 16 89 45 fc 53 50 ff 56 04 89 45 f4 } //1
		$a_01_2 = {39 18 39 18 74 11 81 38 79 74 60 83 74 09 c1 08 02 81 30 79 74 60 83 83 c0 04 e2 e4 } //1
		$a_01_3 = {5c 6c 64 73 68 79 72 2e 6f 6c 64 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}