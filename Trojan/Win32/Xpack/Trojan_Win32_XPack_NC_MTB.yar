
rule Trojan_Win32_XPack_NC_MTB{
	meta:
		description = "Trojan:Win32/XPack.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {74 23 38 78 bb 23 ad 90 01 04 20 b5 a4 21 1a 36 14 90 01 01 34 45 93 03 b8 1b 0c 15 81 09 1f 79 24 90 00 } //01 00 
		$a_01_1 = {39 38 74 65 2e 34 79 } //00 00  98te.4y
	condition:
		any of ($a_*)
 
}