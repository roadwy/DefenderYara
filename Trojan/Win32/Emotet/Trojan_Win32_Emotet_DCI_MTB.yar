
rule Trojan_Win32_Emotet_DCI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b c2 d1 f8 8b c8 33 d2 8b c5 f7 f1 83 c5 01 8a 14 56 30 54 2b ff 3b 6c 24 90 01 01 0f 85 90 00 } //01 00 
		$a_02_1 = {f7 e1 c1 ea 05 6b d2 90 01 01 8b c1 2b c2 8a 14 18 30 14 31 41 3b cf 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}