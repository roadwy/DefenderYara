
rule Trojan_Win32_NanoCore_RPG_MTB{
	meta:
		description = "Trojan:Win32/NanoCore.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 00 33 00 2e 00 32 00 32 00 39 00 2e 00 33 00 34 00 2e 00 31 00 31 00 34 00 3a 00 38 00 31 00 2f 00 90 02 30 2e 00 62 00 6d 00 70 00 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {42 69 6e 64 65 72 } //01 00  Binder
		$a_01_4 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_5 = {41 64 64 53 65 63 6f 6e 64 73 } //01 00  AddSeconds
		$a_01_6 = {49 50 53 74 61 74 75 73 } //01 00  IPStatus
		$a_01_7 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  HttpWebResponse
		$a_01_8 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}