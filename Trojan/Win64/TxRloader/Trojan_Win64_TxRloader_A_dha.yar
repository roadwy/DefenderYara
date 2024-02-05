
rule Trojan_Win64_TxRloader_A_dha{
	meta:
		description = "Trojan:Win64/TxRloader.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 64 00 "
		
	strings :
		$a_01_0 = {25 73 5c 63 6f 6e 66 69 67 5c 54 78 52 5c 25 73 2e 54 78 52 2e 30 2e 72 65 67 74 72 61 6e 73 2d 6d 73 } //64 00 
		$a_41_1 = {54 24 58 44 8b 44 24 44 48 8b 4c 24 58 4c 8d 4c 24 44 ba 00 10 00 00 ff 00 } //00 5d 
	condition:
		any of ($a_*)
 
}