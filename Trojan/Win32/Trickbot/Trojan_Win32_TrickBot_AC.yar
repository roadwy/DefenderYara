
rule Trojan_Win32_TrickBot_AC{
	meta:
		description = "Trojan:Win32/TrickBot.AC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {31 38 35 2e 31 34 32 2e 39 39 2e 31 39 } //02 00 
		$a_01_1 = {56 4e 43 53 52 56 2e 70 64 62 } //01 00 
		$a_01_2 = {2f 4b 20 73 63 68 74 61 73 6b 73 2e 65 78 65 20 7c 6d 6f 72 65 } //01 00 
		$a_01_3 = {2d 2d 61 6c 6c 6f 77 2d 6e 6f 2d 73 61 6e 64 62 6f 78 2d 6a 6f 62 } //00 00 
	condition:
		any of ($a_*)
 
}