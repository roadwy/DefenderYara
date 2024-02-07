
rule Trojan_Win32_CryptInject_ibt{
	meta:
		description = "Trojan:Win32/CryptInject!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 11 81 f2 13 6e 78 07 89 11 83 c0 04 3b f0 90 01 02 83 ee 78 89 75 d0 8b 45 fc 89 45 d4 c7 45 d8 00 1e 00 00 c7 45 dc 4b 54 00 00 c7 45 e0 a5 53 00 00 b8 b8 c7 49 00 89 45 e8 8d 45 f8 50 6a 40 8b 45 f4 50 8b 45 fc 50 90 01 05 81 45 fc 30 54 00 00 8b 45 fc 8d 55 d0 52 ff d0 90 00 } //01 00 
		$a_00_1 = {6d 73 74 73 63 2e 65 78 65 } //00 00  mstsc.exe
	condition:
		any of ($a_*)
 
}