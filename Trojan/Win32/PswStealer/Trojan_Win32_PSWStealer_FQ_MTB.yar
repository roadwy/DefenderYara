
rule Trojan_Win32_PSWStealer_FQ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.FQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 55 08 83 c2 5b 89 95 90 01 04 8b 45 08 05 a0 00 00 00 89 85 90 01 04 8b 4d 08 83 c1 48 89 8d 90 01 04 8b 55 08 83 c2 0b 89 95 90 01 04 8b 45 08 83 c0 0d 89 85 64 fe ff ff 8b 4d 08 90 00 } //0a 00 
		$a_02_1 = {8b 8d e4 fe ff ff 03 4d c0 89 8d 90 01 04 8b 95 90 01 04 0f af 95 90 01 04 89 55 ac 8b 45 ac 0f af 85 90 01 04 89 45 c4 8b 4d e8 3b 8d 90 00 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}