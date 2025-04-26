
rule Backdoor_Win32_Esforsho_A{
	meta:
		description = "Backdoor:Win32/Esforsho.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 61 64 20 66 75 6e 20 2d 31 00 } //1 潬摡映湵ⴠ1
		$a_00_1 = {45 78 65 63 75 74 65 20 2d 31 0d 0a } //1
		$a_03_2 = {68 e8 03 00 00 ff d3 a1 ?? ?? ?? ?? 85 c0 76 10 69 c0 60 ea 00 00 50 ff d3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}