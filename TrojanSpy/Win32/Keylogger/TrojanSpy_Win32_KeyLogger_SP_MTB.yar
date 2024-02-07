
rule TrojanSpy_Win32_KeyLogger_SP_MTB{
	meta:
		description = "TrojanSpy:Win32/KeyLogger.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 44 24 1c c7 44 24 18 00 00 00 00 c7 44 24 14 06 00 02 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 28 40 40 00 c7 04 24 01 00 00 80 } //01 00 
		$a_01_1 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 53 79 73 4d 73 6e 2e 65 78 65 } //00 00  \AppData\Roaming\SysMsn.exe
	condition:
		any of ($a_*)
 
}