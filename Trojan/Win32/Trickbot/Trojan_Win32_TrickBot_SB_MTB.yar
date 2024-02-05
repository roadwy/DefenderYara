
rule Trojan_Win32_TrickBot_SB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 50 6a 40 6a 05 56 ff 90 01 04 00 8b 90 01 04 00 8d 4c 24 0c 6a 01 51 56 c7 44 24 18 e9 00 00 00 ff d7 8d 44 24 08 6a 04 8b 54 24 1c 50 2b d6 70 90 01 01 83 ea 05 70 90 01 01 83 c6 01 89 54 24 10 70 90 01 01 56 ff 90 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}