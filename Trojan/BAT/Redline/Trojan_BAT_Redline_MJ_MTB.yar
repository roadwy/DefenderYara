
rule Trojan_BAT_RedLine_MJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 dd 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3b 00 00 00 83 } //01 00 
		$a_01_1 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 34 65 31 2d 32 31 } //01 00  $$method0x60004e1-21
		$a_01_2 = {54 68 72 65 61 64 57 61 73 53 75 73 70 65 6e 64 65 64 } //01 00  ThreadWasSuspended
		$a_01_3 = {50 61 73 73 77 6f 72 64 45 78 70 69 72 65 64 } //01 00  PasswordExpired
		$a_01_4 = {49 73 4c 6f 67 67 69 6e 67 } //00 00  IsLogging
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RedLine_MJ_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 6f 6c 65 43 61 6e 63 65 6c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ConsoleCancel.g.resources
		$a_01_1 = {43 6f 6e 73 6f 6c 65 4b 65 79 49 6e 66 6f 2e 43 72 79 70 74 6f 2e 46 6f 72 6d 31 } //01 00  ConsoleKeyInfo.Crypto.Form1
		$a_01_2 = {65 34 61 39 33 33 33 64 2d 31 61 38 39 2d 34 61 62 37 2d 38 36 37 39 2d 34 32 34 32 30 37 61 33 63 32 34 61 } //01 00  e4a9333d-1a89-4ab7-8679-424207a3c24a
		$a_01_3 = {43 6f 6e 73 6f 6c 65 43 61 6e 63 65 6c 2e 65 78 65 } //00 00  ConsoleCancel.exe
	condition:
		any of ($a_*)
 
}