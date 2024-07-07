
rule Virus_Win32_Xpaj_gen_C{
	meta:
		description = "Virus:Win32/Xpaj.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 41 04 2e 64 6c 6c c7 41 08 2e 73 63 72 } //1
		$a_03_1 = {61 75 74 6f c7 44 90 01 01 04 72 75 6e 2e c7 44 90 1b 00 08 90 03 03 03 65 78 65 69 6e 66 00 90 09 13 00 c7 04 90 1b 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}