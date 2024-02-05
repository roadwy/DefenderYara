
rule Trojan_Win64_Bazzarldr_GV_MTB{
	meta:
		description = "Trojan:Win64/Bazzarldr.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_02_0 = {10 00 00 49 90 02 02 ba 00 00 00 00 48 90 02 02 ff d3 48 90 02 04 8b 90 02 02 89 90 02 02 48 8b 90 02 02 49 89 90 02 02 48 8b 90 02 02 48 89 90 02 02 e8 90 02 04 8b 90 02 02 48 8b 90 02 02 89 54 90 02 02 48 8d 90 02 02 48 89 90 02 04 48 8b 90 02 02 48 89 90 02 04 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 89 90 02 02 48 8b 90 02 06 ff d0 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  01 00 
		$a_80_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  01 00 
		$a_80_3 = {6d 65 6d 63 70 79 } //memcpy  00 00 
	condition:
		any of ($a_*)
 
}