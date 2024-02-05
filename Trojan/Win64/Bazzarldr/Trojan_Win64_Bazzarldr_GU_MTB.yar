
rule Trojan_Win64_Bazzarldr_GU_MTB{
	meta:
		description = "Trojan:Win64/Bazzarldr.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_80_0 = {53 74 75 70 69 64 20 44 65 66 65 6e 64 65 72 } //Stupid Defender  01 00 
		$a_80_1 = {4c 64 72 4c 6f 61 64 44 6c 6c } //LdrLoadDll  01 00 
		$a_80_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  01 00 
		$a_80_4 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //CryptEncrypt  01 00 
		$a_80_5 = {6d 65 6d 63 70 79 } //memcpy  00 00 
	condition:
		any of ($a_*)
 
}