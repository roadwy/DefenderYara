
rule HackTool_Win32_CheatEngine_RC_MTB{
	meta:
		description = "HackTool:Win32/CheatEngine.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 48 45 41 54 20 50 4f 49 4e 54 42 4c 41 4e 4b 20 48 41 52 44 } //1 CHEAT POINTBLANK HARD
		$a_01_1 = {43 48 45 41 54 20 50 4f 49 4e 54 42 4c 41 4e 4b 20 53 49 4d 50 4c 45 } //1 CHEAT POINTBLANK SIMPLE
		$a_01_2 = {48 61 63 6b 20 45 72 72 6f 72 21 20 50 6c 65 61 73 65 20 52 75 6e 20 41 73 20 55 6c 61 6e 67 20 41 74 61 75 20 52 65 73 74 61 72 74 20 4b 6f 6d 70 75 74 65 72 20 41 6e 64 61 } //1 Hack Error! Please Run As Ulang Atau Restart Komputer Anda
		$a_01_3 = {48 61 63 6b 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 20 48 61 70 70 79 20 63 68 65 61 74 69 6e 67 20 } //1 Hack successfully! Happy cheating 
		$a_01_4 = {57 65 6c 63 6f 6d 65 20 43 68 65 61 74 65 72 73 } //1 Welcome Cheaters
		$a_01_5 = {41 6c 6c 20 49 6e 20 4f 6e 65 20 48 61 63 6b 73 } //1 All In One Hacks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}