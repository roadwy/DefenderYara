
rule Trojan_Win32_TrickBot_Q{
	meta:
		description = "Trojan:Win32/TrickBot.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 7c 7d 70 21 54 32 5a 72 72 6a 31 6b 4b 63 } //00 00  k|}p!T2Zrrj1kKc
	condition:
		any of ($a_*)
 
}