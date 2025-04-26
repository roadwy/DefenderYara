
rule TrojanClicker_Win32_Delf_S{
	meta:
		description = "TrojanClicker:Win32/Delf.S,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 3d 22 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 65 72 22 } //1 @="Internet Exploer"
		$a_01_1 = {42 75 74 74 6f 6e 4d 79 43 6d 70 75 74 65 72 54 6f 53 59 53 33 32 } //2 ButtonMyCmputerToSYS32
		$a_01_2 = {40 3d 22 5b 53 59 53 33 32 44 49 52 5d 6f 64 65 78 6c 2e 65 78 65 22 } //2 @="[SYS32DIR]odexl.exe"
		$a_01_3 = {40 40 40 54 68 75 6e 64 65 72 20 49 45 20 55 70 64 61 74 65 40 40 40 } //2 @@@Thunder IE Update@@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}