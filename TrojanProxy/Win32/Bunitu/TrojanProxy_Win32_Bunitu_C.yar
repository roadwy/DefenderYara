
rule TrojanProxy_Win32_Bunitu_C{
	meta:
		description = "TrojanProxy:Win32/Bunitu.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 64 53 76 63 00 } //01 00 
		$a_01_1 = {c3 78 78 78 78 2f 31 2e 30 20 32 30 30 20 4f 4b 0d 0a } //01 00 
		$a_03_2 = {36 c6 84 28 90 01 02 ff ff 00 36 80 bc 28 90 01 02 ff ff 2f 76 90 00 } //01 00 
		$a_01_3 = {8b 45 08 8b 5d 0c c6 03 30 eb 0e 33 d2 f7 75 14 80 c2 30 36 88 54 2e } //01 00 
		$a_03_4 = {83 c2 08 4e 75 90 01 01 83 ef 04 c6 47 24 03 c7 07 21 00 00 00 6a 25 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}