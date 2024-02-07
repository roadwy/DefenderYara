
rule Trojan_Win32_SmokeLoader_RDB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 f4 8b 45 f4 33 45 f8 89 1d 90 01 04 29 45 e4 89 45 f4 8b 45 cc 29 45 fc 90 00 } //01 00 
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00  kernel32.dll
		$a_01_2 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //00 00  LocalAlloc
	condition:
		any of ($a_*)
 
}