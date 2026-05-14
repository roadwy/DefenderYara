
rule HackTool_Win32_Patcher_B_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {2e 2e 2d 3d 3e 20 43 72 61 63 6b 20 49 6e 66 6f 20 3c 3d 2e 2e } //..-=> Crack Info <=..  1
		$a_80_1 = {43 4f 4e 47 52 41 54 55 4c 41 54 49 4f 4e } //CONGRATULATION  2
		$a_80_2 = {2e 5f 5f 5f 2e 2e 2d 3d 5b 20 20 54 68 65 20 48 69 76 65 20 20 5d 3d 2d 2e 2e 5f 5f 5f 2e } //.___..-=[  The Hive  ]=-..___.  1
		$a_80_3 = {47 50 4d 2d 58 4d 2d 37 35 34 36 37 38 } //GPM-XM-754678  2
		$a_80_4 = {46 69 6c 65 20 53 75 63 63 65 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 } //File Succesfully patched  2
		$a_80_5 = {25 73 2e 42 41 4b } //%s.BAK  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1) >=7
 
}
rule HackTool_Win32_Patcher_B_AMTB_2{
	meta:
		description = "HackTool:Win32/Patcher.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {3a 3a 5b 63 72 61 63 6b 65 64 20 62 79 5d 3a 3a 3a 3a 5b 64 69 61 62 6c 6f 32 6f 6f 32 5d 3a 3a } //::[cracked by]::::[diablo2oo2]::  1
		$a_80_1 = {49 6e 63 6f 72 72 65 63 74 20 76 65 72 73 69 6f 6e 20 6f 72 20 66 69 6c 65 20 61 6c 72 65 61 64 79 20 70 61 74 63 68 65 64 20 21 } //Incorrect version or file already patched !  1
		$a_80_2 = {43 72 61 63 6b 65 72 20 3a } //Cracker :  2
		$a_80_3 = {41 70 70 6c 79 20 74 68 65 20 70 61 74 63 68 } //Apply the patch  1
		$a_80_4 = {6c 63 63 5f 70 61 74 63 68 65 72 } //lcc_patcher  2
		$a_80_5 = {64 69 61 62 6c 6f 32 6f 6f 32 } //diablo2oo2  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=7
 
}