
rule Trojan_Win32_Farfli_CBG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 79 73 32 31 2e 64 6c 6c } //01 00  Consys21.dll
		$a_01_1 = {68 74 74 70 3a 2f 2f 75 73 65 72 73 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d 2f 66 63 67 2d 62 69 6e 2f 63 67 69 5f 67 65 74 5f 70 6f 72 74 72 61 69 74 2e 66 63 67 3f 75 69 6e 73 } //01 00  http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins
		$a_01_2 = {53 65 72 76 65 72 5c 44 65 62 75 67 5c 44 48 4c 32 30 31 32 2e 70 64 62 } //01 00  Server\Debug\DHL2012.pdb
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}