
rule Trojan_Win32_Redosdru_D{
	meta:
		description = "Trojan:Win32/Redosdru.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 11 8a 14 01 80 ea 08 80 f2 20 88 14 01 41 3b ce 7c ef } //01 00 
		$a_01_1 = {65 3a 5c 6a 6f 62 5c 67 68 30 73 74 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //01 00 
		$a_01_2 = {47 48 30 53 54 43 } //00 00 
	condition:
		any of ($a_*)
 
}