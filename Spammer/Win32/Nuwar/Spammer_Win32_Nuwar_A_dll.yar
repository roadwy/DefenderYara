
rule Spammer_Win32_Nuwar_A_dll{
	meta:
		description = "Spammer:Win32/Nuwar.A!dll,SIGNATURE_TYPE_PEHSTR,07 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6f 52 6b 00 68 4d 69 63 72 } //1 潨歒栀楍牣
		$a_01_1 = {68 6c 65 67 65 68 72 69 76 69 68 62 75 67 50 68 53 65 44 65 } //3 hlegehrivihbugPhSeDe
		$a_01_2 = {74 61 73 6b 64 69 72 3b 61 64 69 72 3b } //3 taskdir;adir;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=6
 
}