
rule Trojan_Win32_Gobfy_A{
	meta:
		description = "Trojan:Win32/Gobfy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 77 00 67 00 65 00 74 00 20 00 31 00 32 00 2e 00 30 00 } //01 00  User-Agent: wget 12.0
		$a_01_1 = {8b c1 33 d2 f7 f3 8a 04 3a 8a 14 31 32 d0 88 14 31 41 3b cd 72 ea } //00 00 
	condition:
		any of ($a_*)
 
}