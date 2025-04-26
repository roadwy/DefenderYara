
rule Worm_Win32_Autorun_HO{
	meta:
		description = "Worm:Win32/Autorun.HO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 08 00 00 00 62 32 65 2e 65 78 65 00 } //1
		$a_02_1 = {65 63 68 6f 20 5b 61 75 74 6f 72 75 6e 5d 20 3e 3e 20 25 25 ?? 3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}