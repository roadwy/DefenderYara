
rule Trojan_Win32_Redosdru_W{
	meta:
		description = "Trojan:Win32/Redosdru.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 00 4d c6 45 01 5a 66 81 7d 00 4d 5a 74 07 5f 5e 5d } //01 00 
		$a_01_1 = {c6 07 4d c6 47 01 5a ff d5 66 81 3f 4d 5a 74 08 5f 5e 5d } //02 00 
		$a_01_2 = {81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 5d 5b } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}