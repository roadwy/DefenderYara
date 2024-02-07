
rule Trojan_Win32_Emotet_B_MTB{
	meta:
		description = "Trojan:Win32/Emotet.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_02_1 = {8b c3 8d 70 02 eb 03 90 01 03 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 41 8a 04 53 30 44 39 ff 3b cd 75 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}