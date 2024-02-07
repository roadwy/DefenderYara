
rule Trojan_Win32_Lokibot_VALC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.VALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc } //01 00 
		$a_81_1 = {57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 46 6f 75 6e 64 61 74 69 6f 6e 5c 42 79 74 65 53 74 72 65 61 6d 48 61 6e 64 6c 65 72 73 } //02 00  Windows Media Foundation\ByteStreamHandlers
		$a_01_2 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff } //02 00 
		$a_01_3 = {89 45 dc c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 4d d8 ff 55 } //00 00 
	condition:
		any of ($a_*)
 
}