
rule Trojan_Win32_Emotet_CM{
	meta:
		description = "Trojan:Win32/Emotet.CM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 47 48 57 45 68 23 67 42 57 52 47 23 23 23 40 33 35 54 47 57 45 67 2f 2f 2f 47 45 57 2e 70 64 62 } //01 00 
		$a_01_1 = {51 45 68 6a 65 6a 65 68 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}