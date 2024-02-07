
rule Trojan_Win32_CobaltStrike_BP_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 39 8e e3 38 f7 e7 8b c7 47 c1 ea 03 8d 0c d2 c1 e1 02 2b c1 8a 80 90 01 04 30 06 3b fb 72 90 00 } //01 00 
		$a_01_1 = {41 56 42 79 70 61 73 73 2e 70 64 62 } //01 00  AVBypass.pdb
		$a_01_2 = {68 74 74 70 5f 64 6c 6c 2e 64 61 74 } //00 00  http_dll.dat
	condition:
		any of ($a_*)
 
}