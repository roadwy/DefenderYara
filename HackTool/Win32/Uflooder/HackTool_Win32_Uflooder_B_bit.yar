
rule HackTool_Win32_Uflooder_B_bit{
	meta:
		description = "HackTool:Win32/Uflooder.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 59 00 4e 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 } //01 00  SYN Flood
		$a_01_1 = {49 00 43 00 4d 00 50 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 } //01 00  ICMP Flood
		$a_01_2 = {55 00 44 00 50 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 } //01 00  UDP Flood
		$a_01_3 = {54 00 43 00 50 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 } //01 00  TCP Flood
		$a_01_4 = {45 00 73 00 74 00 61 00 62 00 6c 00 69 00 73 00 68 00 65 00 64 00 20 00 41 00 74 00 74 00 61 00 63 00 6b 00 } //00 00  Established Attack
	condition:
		any of ($a_*)
 
}