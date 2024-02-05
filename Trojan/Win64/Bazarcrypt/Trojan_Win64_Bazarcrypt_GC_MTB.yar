
rule Trojan_Win64_Bazarcrypt_GC_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_02_0 = {88 10 8b 2d 90 02 04 0f b6 90 02 02 0f b6 90 02 02 03 c2 99 bb 90 02 04 f7 fb 0f b6 90 02 02 8a 14 90 02 02 8b 44 90 02 02 30 14 07 8b 44 90 02 02 47 3b f8 7c 90 00 } //01 00 
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  01 00 
		$a_80_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  00 00 
	condition:
		any of ($a_*)
 
}