
rule PWS_Win32_Wowsteal_ZA{
	meta:
		description = "PWS:Win32/Wowsteal.ZA,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {43 52 41 43 4b 49 4e 47 } //1 CRACKING
		$a_00_2 = {77 6f 77 2e 65 78 65 } //1 wow.exe
		$a_01_3 = {57 51 57 2e 65 78 65 } //1 WQW.exe
		$a_01_4 = {57 76 57 2e 65 78 65 } //1 WvW.exe
		$a_00_5 = {61 63 74 69 6f 6e 3d 67 65 74 75 73 65 72 } //1 action=getuser
		$a_00_6 = {47 61 6d 65 48 4d 4f 76 65 72 } //1 GameHMOver
		$a_00_7 = {54 68 72 65 61 64 46 61 6c 73 65 } //1 ThreadFalse
		$a_00_8 = {52 61 76 52 75 6e 65 69 70 } //1 RavRuneip
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_10 = {4a 75 6d 70 48 6f 6f 6b 4f 6e } //1 JumpHookOn
		$a_00_11 = {61 63 74 69 6f 6e 3d 67 65 74 79 78 6c 6f 67 69 6e 26 75 3d } //1 action=getyxlogin&u=
		$a_00_12 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}