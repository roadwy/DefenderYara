
rule Trojan_Win32_Emotet_DCG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d5 8b c6 33 d2 b9 90 01 04 f7 f1 8a 04 3e 8a 14 53 32 c2 88 04 3e 8b 44 24 90 02 04 3b f0 75 90 00 } //01 00 
		$a_02_1 = {6a 00 ff 15 38 c6 40 00 8b 44 24 90 01 01 6a 90 01 01 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 90 01 01 8a 04 50 30 01 90 02 03 3b 74 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}