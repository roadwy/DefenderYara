
rule Virus_Win32_Xpaj_gen_B{
	meta:
		description = "Virus:Win32/Xpaj.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {61 75 74 6f c7 ?? ?? 04 72 75 6e 2e c7 ?? ?? (08 69 6e 66|08 65 78 65) 00 } //1
		$a_02_1 = {2e 65 78 65 c7 ?? 04 2e 64 6c 6c c7 ?? 08 2e 73 63 72 c7 ?? 0c 2e 73 79 73 } //1
		$a_02_2 = {2e 63 6f 6d 0f 84 ?? ?? 00 00 81 ?? 2e 69 6e 66 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}