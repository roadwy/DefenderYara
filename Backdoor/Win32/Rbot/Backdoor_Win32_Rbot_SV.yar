
rule Backdoor_Win32_Rbot_SV{
	meta:
		description = "Backdoor:Win32/Rbot.SV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {28 28 02 62 79 20 42 4f 54 43 4f 4d 29 29 } //1 ⠨戂⁹佂䍔䵏⤩
		$a_00_1 = {77 69 6e 6c 6f 6c 78 2e 65 78 65 } //1 winlolx.exe
		$a_01_2 = {57 69 6e 64 6f 77 73 20 4c 6f 4c 20 4c 61 79 65 72 } //1 Windows LoL Layer
		$a_01_3 = {42 6f 54 7c } //1 BoT|
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}