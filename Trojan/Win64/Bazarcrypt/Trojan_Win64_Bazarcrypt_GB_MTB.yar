
rule Trojan_Win64_Bazarcrypt_GB_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {48 98 48 03 90 02 02 8b 55 90 02 02 48 63 90 02 02 48 03 90 02 02 0f b6 90 02 02 4c 8b 05 90 02 04 0f b6 90 02 02 4c 01 90 02 02 0f b6 90 02 02 31 ca 88 10 83 45 90 02 02 01 8b 45 90 02 02 3b 45 90 02 02 0f 9c c0 84 c0 0f 85 90 00 } //01 00 
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  00 00 
	condition:
		any of ($a_*)
 
}