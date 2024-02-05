
rule Trojan_Win32_CryptInject_O_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.O!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 00 52 00 79 00 6b 00 61 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_02_1 = {47 4f 66 66 69 63 90 0f 01 00 90 00 } //01 00 
		$a_00_2 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}