
rule Trojan_Win64_CobaltStrike_NS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 10 00 00 8b 90 01 01 33 90 01 01 ff 15 90 00 } //01 00 
		$a_01_1 = {55 74 69 6c 45 78 70 6f 72 74 46 75 6e 63 74 69 6f 6e 73 } //02 00  UtilExportFunctions
		$a_03_2 = {c5 fd 7f 09 c5 fd 7f 51 90 01 01 c5 fd 7f 59 90 01 01 c5 fd 7f 61 90 01 01 c5 fe 6f 8a 90 01 04 c5 fe 6f 92 90 01 04 c5 fe 6f 9a 90 01 04 c5 fe 6f a2 90 01 04 c5 fd 7f 89 90 01 04 c5 fd 7f 91 90 01 04 c5 fd 7f 99 90 01 04 c5 fd 7f a1 90 01 04 48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}