
rule Trojan_Win32_Emotet_DP{
	meta:
		description = "Trojan:Win32/Emotet.DP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 4b 6b 61 73 64 66 6c 63 61 77 6b 6c 62 6a 6c 62 6c 6b 6e 72 77 63 6c 74 6b 78 77 62 74 63 6c 6b 77 65 6a 62 63 74 30 6c 77 6b 62 6a 67 72 78 6c 77 6b 6d 74 72 6b 6c 77 65 72 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}