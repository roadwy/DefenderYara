
rule Trojan_Win32_Emotet_NG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 90 02 23 83 c4 0c 90 02 23 f7 d8 1b c0 90 02 96 83 c4 0c ff d0 90 00 } //01 00 
		$a_02_1 = {81 e2 ff 00 00 00 c1 90 02 02 8b 90 02 03 0b 90 02 02 c1 90 02 02 33 90 01 01 3b 74 90 02 02 89 90 02 02 8d 76 90 02 04 0f 90 02 4b 81 90 01 01 ff 00 00 00 90 02 03 32 90 01 01 8d 90 02 02 8b 90 02 02 3b 90 02 02 90 02 0f e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}