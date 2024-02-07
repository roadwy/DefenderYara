
rule TrojanSpy_Win32_Delf_DC{
	meta:
		description = "TrojanSpy:Win32/Delf.DC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 74 70 2e 6e 61 72 6f 64 2e 72 75 } //01 00  ftp.narod.ru
		$a_00_1 = {48 61 63 6b 6c 6f 67 67 73 } //01 00  Hackloggs
		$a_02_2 = {53 79 73 74 65 6d 33 32 5c 54 65 73 74 5c 44 69 72 90 01 01 5c 44 69 72 90 02 40 5c 73 63 72 65 65 6e 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}