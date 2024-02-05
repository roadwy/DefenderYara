
rule Trojan_Win32_Starter_H{
	meta:
		description = "Trojan:Win32/Starter.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {65 3a 5c 66 72 65 65 5c 77 65 62 31 2e 30 5c 53 76 63 68 6f 73 74 5c 52 65 6c 65 61 73 65 5c 53 56 43 48 4f 53 54 2e 70 64 62 } //02 00 
		$a_01_1 = {5c 64 6f 64 6f 6c 6f 6f 6b 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}