
rule Trojan_Win32_CryptInject_AC_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.AC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 67 00 6e 00 20 00 46 00 6e 00 63 00 64 00 63 00 67 00 65 00 74 00 } //01 00 
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 6f 00 6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 } //01 00 
		$a_01_2 = {4f 00 72 00 64 00 69 00 6e 00 61 00 72 00 79 00 53 00 6f 00 66 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}