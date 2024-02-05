
rule Trojan_Win64_Bazzarldr_GW_MTB{
	meta:
		description = "Trojan:Win64/Bazzarldr.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_02_0 = {31 f6 48 89 90 02 02 31 d2 49 89 90 02 02 41 b9 00 10 00 00 ff 15 90 02 04 48 89 90 02 02 48 89 90 02 02 4c 89 90 02 02 49 89 90 02 02 e8 90 02 04 8b 45 00 48 90 02 04 90 02 04 89 44 90 02 02 48 90 02 04 48 90 02 04 31 d2 41 b8 01 00 00 00 45 31 90 02 02 ff 15 90 02 04 85 c0 0f 90 00 } //01 00 
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  01 00 
		$a_80_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  00 00 
	condition:
		any of ($a_*)
 
}