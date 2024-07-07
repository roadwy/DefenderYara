
rule Backdoor_Win32_Mutihack_A{
	meta:
		description = "Backdoor:Win32/Mutihack.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 4d 75 74 69 25 64 48 61 63 6b } //3 Global\Muti%dHack
		$a_01_1 = {6d 75 74 69 68 61 63 6b 2e 64 6c 6c } //1 mutihack.dll
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 53 74 61 72 74 75 70 20 25 73 } //1 rundll32.exe %s, Startup %s
		$a_01_3 = {62 62 73 2e 4d 75 74 69 48 61 63 6b 2e 63 6f 6d } //2 bbs.MutiHack.com
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}