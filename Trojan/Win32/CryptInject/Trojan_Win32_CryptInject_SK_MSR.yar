
rule Trojan_Win32_CryptInject_SK_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.SK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 78 00 6f 00 72 00 62 00 69 00 74 00 } //01 00 
		$a_01_1 = {62 00 61 00 72 00 72 00 6f 00 77 00 64 00 65 00 73 00 74 00 69 00 6c 00 6c 00 } //01 00 
		$a_00_2 = {6a 00 72 00 41 00 54 00 54 00 41 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}