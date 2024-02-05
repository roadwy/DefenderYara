
rule Trojan_Win32_Batload_K_MSR{
	meta:
		description = "Trojan:Win32/Batload.K!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 78 74 65 72 6e 61 6c 63 68 65 63 6b 73 73 6f 2e 63 6f 6d 2f 67 35 69 30 6e 71 } //externalchecksso.com/g5i0nq  01 00 
		$a_81_1 = {6e 65 77 74 65 73 74 2e 62 61 74 } //01 00 
		$a_81_2 = {61 76 6f 6c 6b 6f 76 5c 78 36 34 5c 52 65 6c 65 61 73 65 20 47 61 72 62 5c 61 76 6f 6c 6b 6f 76 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}