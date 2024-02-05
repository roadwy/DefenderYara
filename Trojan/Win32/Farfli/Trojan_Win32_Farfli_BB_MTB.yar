
rule Trojan_Win32_Farfli_BB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 8b 5c 24 58 4d 88 14 1f 47 41 88 54 24 48 89 7c 24 10 85 ed 0f 84 } //01 00 
		$a_01_1 = {50 8b c3 8b c3 58 83 ea 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}