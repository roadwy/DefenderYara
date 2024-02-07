
rule Trojan_Win32_DanaBot_NEAA_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {77 72 74 70 73 64 66 68 6c 7a 63 76 62 6e 6d } //05 00  wrtpsdfhlzcvbnm
		$a_01_1 = {71 65 79 75 69 6f 61 71 65 79 75 69 6f 61 71 65 } //05 00  qeyuioaqeyuioaqe
		$a_01_2 = {77 73 63 70 72 6f 78 79 73 74 75 62 2e 64 6c 6c } //05 00  wscproxystub.dll
		$a_01_3 = {44 3a 5c 42 75 69 6c 64 73 5c 53 65 72 76 65 72 5c 36 34 78 5c 44 65 62 75 67 5c 46 53 5f 43 6f 6e 66 69 67 5c 43 6f 6e 66 69 67 2e 64 61 74 } //05 00  D:\Builds\Server\64x\Debug\FS_Config\Config.dat
		$a_01_4 = {68 70 66 76 75 77 37 33 2e 64 6c 6c } //01 00  hpfvuw73.dll
		$a_01_5 = {53 79 73 74 65 6d 2e 45 6e 74 65 72 70 72 69 73 65 53 65 72 76 69 63 65 73 2e 54 68 75 6e 6b 2e 64 6c 6c } //00 00  System.EnterpriseServices.Thunk.dll
	condition:
		any of ($a_*)
 
}