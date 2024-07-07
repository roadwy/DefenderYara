
rule Backdoor_Win32_Rcontrole{
	meta:
		description = "Backdoor:Win32/Rcontrole,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 62 69 6c 73 65 62 79 2e 62 61 74 } //1 ubilseby.bat
		$a_01_1 = {2f 6b 65 79 2e 70 68 70 3f 6b 65 79 3d } //1 /key.php?key=
		$a_01_2 = {2f 62 75 66 66 65 72 2e 70 68 70 3f 62 75 66 66 65 72 3d } //1 /buffer.php?buffer=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}