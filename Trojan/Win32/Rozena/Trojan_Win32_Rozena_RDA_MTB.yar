
rule Trojan_Win32_Rozena_RDA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 43 56 56 } //01 00 
		$a_01_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //02 00 
		$a_01_2 = {0f b6 75 10 8b 45 08 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 } //00 00 
	condition:
		any of ($a_*)
 
}