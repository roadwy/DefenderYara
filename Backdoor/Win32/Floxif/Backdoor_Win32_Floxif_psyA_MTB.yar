
rule Backdoor_Win32_Floxif_psyA_MTB{
	meta:
		description = "Backdoor:Win32/Floxif.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ec 8b 55 08 85 d2 75 15 e8 69 fe ff ff c7 00 16 00 00 00 e8 ?? ?? ?? ff 83 c8 ff 5d c3 83 6a 08 01 79 09 52 e8 ?? ?? ?? 00 59 5d c3 8b 02 8a 08 40 89 02 0f b6 c1 5d c3 8b ff 55 8b ec 5d e9 b9 } //1
		$a_03_1 = {75 18 e8 49 ?? ?? ?? c7 00 16 00 00 00 e8 ?? ?? ?? ff 83 c8 ff e9 67 01 00 00 8b 40 0c } //1
		$a_03_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d ?? ?? ?? 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}