
rule Worm_Win32_Passdown{
	meta:
		description = "Worm:Win32/Passdown,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \Autorun.inf
		$a_03_1 = {4f 8d 4f 01 8a 47 01 47 84 c0 75 f8 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 07 a1 ?? ?? ?? ?? 89 57 04 8a 15 ?? ?? ?? ?? 89 47 08 8d 84 24 ?? ?? 00 00 50 51 88 57 0c ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}