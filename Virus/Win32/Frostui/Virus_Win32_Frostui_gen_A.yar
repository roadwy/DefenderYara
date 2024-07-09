
rule Virus_Win32_Frostui_gen_A{
	meta:
		description = "Virus:Win32/Frostui.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {66 3d 51 04 0f 85 ?? ?? ?? ?? c1 e8 10 83 e0 0f 66 3d 01 00 0f 8e } //1
		$a_01_1 = {ae 75 fd c6 07 00 83 ef 05 c7 07 2e 65 78 65 } //1
		$a_03_2 = {3d 2e 64 6f 63 0f 85 ?? ?? ?? ?? 6a 02 50 ff 75 08 e8 } //1
		$a_01_3 = {e9 04 00 00 00 2a 2e 2a 00 68 } //1
		$a_01_4 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 47 75 65 73 74 20 2f 61 64 64 } //1 net localgroup administrators Guest /add
		$a_01_5 = {6e 65 74 20 73 68 61 72 65 20 43 24 3d 43 3a 20 2f 67 72 61 6e 74 3a 65 76 65 72 79 6f 6e 65 2c 66 75 6c 6c } //1 net share C$=C: /grant:everyone,full
		$a_01_6 = {34 30 53 31 31 38 54 32 30 31 33 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}