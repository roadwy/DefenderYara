
rule Trojan_Win32_TrickBot_CA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 8d 49 00 8b f0 c1 e6 13 c1 e8 0d 0b c6 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 8a 4a 01 42 84 c9 75 } //01 00 
		$a_02_1 = {6a 00 ff 15 90 01 04 c7 05 90 01 04 03 80 00 00 c7 05 90 01 04 01 68 00 00 c7 05 90 01 04 01 00 00 00 c7 05 90 01 04 40 00 00 00 c7 05 90 01 04 00 10 00 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}