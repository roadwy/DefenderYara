
rule Trojan_Win32_OffLoader_PGOG_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.PGOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 68 6f 75 73 65 73 69 63 65 2e 73 70 61 63 65 } ////housesice.space  5
		$a_80_1 = {2f 2f 63 6f 61 6c 73 75 62 73 74 61 6e 63 65 2e 63 66 64 } ////coalsubstance.cfd  5
		$a_01_2 = {5c 00 73 00 74 00 61 00 72 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 67 00 65 00 74 00 00 00 22 00 03 00 9a 80 5c 00 73 00 74 00 61 00 72 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 22 } //5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}