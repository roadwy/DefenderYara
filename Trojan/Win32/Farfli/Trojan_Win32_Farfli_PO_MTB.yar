
rule Trojan_Win32_Farfli_PO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.PO!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 83 c0 01 83 ee 01 75 e4 } //01 00 
		$a_01_1 = {89 28 8b e8 a1 70 55 44 00 33 c5 50 89 65 f0 ff 75 fc c7 45 fc ff ff ff ff 8d 45 f4 64 a3 00 00 00 00 } //01 00 
		$a_01_2 = {8a 0e 88 0a 42 46 3a cb 74 03 4f 75 f3 } //00 00 
	condition:
		any of ($a_*)
 
}