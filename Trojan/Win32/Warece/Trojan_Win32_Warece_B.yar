
rule Trojan_Win32_Warece_B{
	meta:
		description = "Trojan:Win32/Warece.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 6f 77 66 78 2e 64 6c 6c 00 4d 47 42 00 4d 47 4f } //2
		$a_03_1 = {66 8b 45 0a 66 3b 05 ?? ?? ?? ?? 75 02 b3 01 56 } //2
		$a_01_2 = {2d 2d 53 41 56 45 54 4f } //1 --SAVETO
		$a_01_3 = {50 50 4a 4f 42 00 } //1 偐佊B
		$a_01_4 = {47 45 54 54 41 53 4b 00 } //1 䕇呔十K
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}