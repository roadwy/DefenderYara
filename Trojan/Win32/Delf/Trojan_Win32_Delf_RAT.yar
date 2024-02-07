
rule Trojan_Win32_Delf_RAT{
	meta:
		description = "Trojan:Win32/Delf.RAT,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 45 fc b9 90 01 04 e8 90 01 02 ff ff 8b 55 fc 8b c3 e8 90 01 02 ff ff 8b c3 e8 90 01 02 ff ff e8 90 01 02 ff ff ba 90 01 04 8b c3 e8 90 01 04 e8 90 01 04 e8 90 01 04 ba 90 01 04 8b c3 e8 90 01 04 e8 90 01 04 e8 90 01 04 ba 90 01 04 8b c3 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff ba 90 01 04 8b c3 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff ba 90 01 04 8b c3 e8 90 01 02 ff ff e8 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //0a 00 
		$a_03_1 = {75 23 6a 00 8d 45 fc b9 90 01 04 8b 15 90 01 04 e8 90 01 04 8b 45 fc e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 90 00 } //0a 00 
		$a_00_2 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //05 00  system32\drivers\etc\hosts
		$a_00_3 = {57 69 6e 45 78 65 63 } //01 00  WinExec
		$a_02_4 = {31 32 37 2e 30 2e 30 2e 31 20 90 02 30 2e 63 6f 6d 90 00 } //01 00 
		$a_02_5 = {39 2e 39 2e 39 2e 39 20 90 02 30 2e 63 6f 6d 90 00 } //01 00 
		$a_02_6 = {69 66 20 65 78 69 73 74 90 02 20 67 6f 74 6f 90 02 20 74 72 79 90 02 20 64 65 6c 20 25 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}