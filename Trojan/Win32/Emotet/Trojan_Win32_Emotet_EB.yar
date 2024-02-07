
rule Trojan_Win32_Emotet_EB{
	meta:
		description = "Trojan:Win32/Emotet.EB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 37 00 41 00 2f 00 4b 00 51 00 44 00 53 00 2b 00 } //01 00  47A/KQDS+
		$a_01_1 = {58 00 67 00 65 00 34 00 79 00 37 00 42 00 3c 00 30 00 39 00 33 00 } //00 00  Xge4y7B<093
	condition:
		any of ($a_*)
 
}