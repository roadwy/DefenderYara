
rule Trojan_Win32_Emotet_SR_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 65 72 6d 69 73 73 69 6f 6e 20 64 65 6e 69 65 64 } //01 00 
		$a_01_1 = {73 65 63 74 69 6f 6e 63 69 74 79 5c 77 6f 6d 61 6e 65 73 70 65 63 69 61 6c 6c 79 5c 66 61 72 6d 53 74 75 64 79 5c 68 6f 77 4c 65 73 73 5c 43 61 72 64 43 61 73 65 5c 61 62 6f 75 74 74 6f 74 61 6c 5c 43 6f 6d 70 61 72 65 45 64 67 65 4d 6f 74 68 65 72 2e 70 64 62 } //01 00 
		$a_01_2 = {42 00 6f 00 61 00 72 00 6e 00 6f 00 75 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_SR_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SR!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75 } //00 00 
	condition:
		any of ($a_*)
 
}