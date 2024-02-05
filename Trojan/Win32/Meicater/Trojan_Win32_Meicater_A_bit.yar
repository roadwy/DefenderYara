
rule Trojan_Win32_Meicater_A_bit{
	meta:
		description = "Trojan:Win32/Meicater.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 73 00 79 00 73 00 00 00 72 00 62 00 00 00 77 00 62 00 } //01 00 
		$a_03_1 = {31 c0 3b 85 90 01 04 8d 14 08 74 90 01 01 31 14 83 40 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}