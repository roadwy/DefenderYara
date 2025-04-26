
rule Trojan_Win32_Swisyn_ASI_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 55 55 ff d3 3b c5 75 0a 68 e0 ?? a4 00 55 55 55 ff d3 8b 35 2c ?? a4 00 6a ff 8d 4c 24 20 55 51 6a 02 89 7c 24 2c 89 44 24 30 ff d6 } //3
		$a_03_1 = {a4 00 ff d7 8b 1d ac ?? a4 00 50 ff d3 68 bc ?? a4 00 68 a0 ?? a4 00 8b f0 ff d7 50 ff d3 } //1
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 79 00 73 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 73 00 5c 00 52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 } //2 Software\Sysinternals\RootkitRevealer
		$a_01_3 = {52 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 6d 00 75 00 73 00 74 00 20 00 62 00 65 00 20 00 72 00 75 00 6e 00 20 00 66 00 72 00 6f 00 6d 00 20 00 74 00 68 00 65 00 20 00 63 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 } //2 RootkitRevealer must be run from the console
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}