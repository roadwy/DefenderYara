
rule Worm_Win32_Autorun_KA_MTB{
	meta:
		description = "Worm:Win32/Autorun.KA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_1 = {3a 5c 77 69 6e 64 6f 77 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 :\windows\svchost.exe
		$a_01_2 = {73 68 65 6c 6c 41 75 74 6f 72 75 6e 63 6f 6d 6d 61 6e 64 3d } //1 shellAutoruncommand=
		$a_01_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 44 69 73 61 6c 6c 6f 77 52 75 6e } //1 CurrentVersion\Policies\Explorer\DisallowRun
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}