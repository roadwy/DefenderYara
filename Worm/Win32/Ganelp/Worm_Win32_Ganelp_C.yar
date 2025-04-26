
rule Worm_Win32_Ganelp_C{
	meta:
		description = "Worm:Win32/Ganelp.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 64 3a 61 65 6c 2a 6e 45 3a 3a } //1 bd:ael*nE::
		$a_01_1 = {67 46 73 6f 6d 65 72 61 6c 50 72 69 } //1 gFsomeralPri
		$a_01_2 = {53 61 45 67 56 65 65 74 75 41 52 65 6c 78 } //1 SaEgVeetuARelx
		$a_03_3 = {03 4d fc 0f be 51 05 83 fa 73 75 ?? a1 ?? ?? ?? ?? 03 45 fc 0f be 48 08 83 f9 74 75 ?? 8b ?? ?? ?? ?? ?? 03 55 fc 0f be 42 0c 83 f8 6e 75 ?? 8b ?? ?? ?? ?? ?? 03 4d fc 0f be 51 0f 83 fa 77 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}