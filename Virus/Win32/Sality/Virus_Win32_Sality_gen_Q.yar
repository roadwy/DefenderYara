
rule Virus_Win32_Sality_gen_Q{
	meta:
		description = "Virus:Win32/Sality.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 64 67 8b 1e 30 00 85 db 78 90 09 19 00 c7 85 90 01 04 22 22 22 22 c7 85 90 01 04 33 33 33 33 e9 90 01 01 00 00 00 90 00 } //1
		$a_03_1 = {68 fe 01 00 00 50 6a 00 ff 95 90 01 04 85 c0 74 90 01 01 8b c8 48 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}