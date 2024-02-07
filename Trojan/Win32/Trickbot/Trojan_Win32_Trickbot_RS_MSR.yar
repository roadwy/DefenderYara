
rule Trojan_Win32_Trickbot_RS_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.RS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {f3 a5 68 8c 44 45 00 e8 9b fd ff ff 83 c4 0c ff d3 6a 00 6a 00 68 84 44 45 00 6a 00 ff 15 a8 04 42 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //01 00  VirtualAllocExNuma
		$a_01_2 = {45 00 72 00 61 00 73 00 65 00 20 00 65 00 76 00 65 00 72 00 79 00 74 00 68 00 69 00 6e 00 67 00 } //01 00  Erase everything
		$a_01_3 = {4f 00 70 00 65 00 6e 00 20 00 74 00 68 00 69 00 73 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //00 00  Open this document
	condition:
		any of ($a_*)
 
}