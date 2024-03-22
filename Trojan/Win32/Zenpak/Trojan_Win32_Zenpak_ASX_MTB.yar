
rule Trojan_Win32_Zenpak_ASX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 00 6f 00 6f 00 64 00 36 00 67 00 72 00 61 00 73 00 73 00 2e 00 7a 00 51 00 6d 00 75 00 6c 00 74 00 69 00 70 00 6c 00 79 00 77 00 65 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 2e 00 4b 00 79 00 } //02 00  good6grass.zQmultiplyweremoved.Ky
		$a_01_1 = {61 00 46 00 72 00 75 00 69 00 74 00 66 00 75 00 6c 00 79 00 65 00 61 00 72 00 73 00 6b 00 6d 00 61 00 6e 00 64 00 61 00 79 00 73 00 74 00 68 00 69 00 72 00 64 00 } //00 00  aFruitfulyearskmandaysthird
	condition:
		any of ($a_*)
 
}