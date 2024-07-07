
rule Backdoor_Win32_Lisfel_C{
	meta:
		description = "Backdoor:Win32/Lisfel.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 75 73 65 72 2e 64 6c 6c 00 } //1
		$a_01_1 = {77 6c 75 70 64 61 74 65 2e 65 78 65 00 } //1
		$a_01_2 = {77 6c 2d 63 6d 64 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 31 2e 70 64 62 } //1 wl-cmd\Release\dll1.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}