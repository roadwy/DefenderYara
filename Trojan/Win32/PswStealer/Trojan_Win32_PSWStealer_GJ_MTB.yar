
rule Trojan_Win32_PSWStealer_GJ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b d9 8a 44 0a ff 30 44 0f ff 49 75 f5 03 fb 29 5d 10 0f 84 } //05 00 
		$a_02_1 = {0f b6 13 32 d0 c1 e8 90 01 01 33 04 96 43 49 75 f1 90 00 } //01 00 
		$a_01_2 = {53 48 43 68 61 6e 67 65 4e 6f 74 69 66 79 52 65 67 69 73 74 65 72 } //01 00 
		$a_01_3 = {52 65 67 69 73 74 65 72 45 76 65 6e 74 53 6f 75 72 63 65 } //01 00 
		$a_01_4 = {73 72 61 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}