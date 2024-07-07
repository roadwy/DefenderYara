
rule Trojan_Win32_Trickbot_STX{
	meta:
		description = "Trojan:Win32/Trickbot.STX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 0a 68 46 82 00 00 6a 00 8b f8 ff d6 } //1
		$a_00_1 = {64 7a 36 37 6a 58 68 52 } //1 dz67jXhR
		$a_00_2 = {46 72 4a 58 57 58 7a 6e 41 6d 50 32 79 36 59 6a 30 68 65 52 52 32 69 44 69 6d 50 45 38 57 64 37 7a 61 43 75 6c 57 78 34 36 68 35 4a 67 } //1 FrJXWXznAmP2y6Yj0heRR2iDimPE8Wd7zaCulWx46h5Jg
		$a_00_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //1 VirtualAllocExNuma
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}