
rule Trojan_Win32_NetLoader_RPJ_MTB{
	meta:
		description = "Trojan:Win32/NetLoader.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f3 a5 6a 00 6a 00 50 66 a5 8d 45 a8 50 6a 00 a4 ff 15 } //01 00 
		$a_01_1 = {51 6a 00 6a 00 6a 10 6a 00 6a 00 6a 00 6a 00 50 ff 15 } //01 00 
		$a_01_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 4a 6f 70 61 2e 65 78 65 } //01 00  AppData\Local\Temp\Jopa.exe
		$a_01_3 = {63 64 6e 2d 31 31 31 2e 61 6e 6f 6e 66 69 6c 65 73 2e 63 6f 6d } //01 00  cdn-111.anonfiles.com
		$a_01_4 = {58 79 69 5f 31 2e 65 78 65 } //00 00  Xyi_1.exe
	condition:
		any of ($a_*)
 
}