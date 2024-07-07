
rule Virus_Win32_Weird_F{
	meta:
		description = "Virus:Win32/Weird.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {60 e8 00 00 00 00 5d 81 c5 03 02 00 00 } //1
		$a_02_1 = {c7 00 2e 65 78 65 c6 40 04 00 33 d2 52 68 22 00 00 00 68 01 00 00 00 52 52 68 00 00 00 40 8d 85 90 01 03 00 50 ff 57 08 83 f8 ff 74 2b 8b d0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}