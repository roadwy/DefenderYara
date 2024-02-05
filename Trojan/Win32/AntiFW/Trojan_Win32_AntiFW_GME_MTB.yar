
rule Trojan_Win32_AntiFW_GME_MTB{
	meta:
		description = "Trojan:Win32/AntiFW.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 59 47 51 56 57 68 54 } //01 00 
		$a_01_1 = {44 49 65 20 44 61 74 65 69 20 69 73 74 20 6e 69 63 68 74 } //01 00 
		$a_01_2 = {40 2e 6e 65 6f 6c 69 74 } //01 00 
		$a_01_3 = {40 2e 50 54 44 61 74 61 } //01 00 
		$a_01_4 = {2e 53 45 46 43 4d 44 } //01 00 
		$a_01_5 = {5c 4c 61 6e 6f 76 61 74 69 6f 6e 5c 50 69 63 74 75 72 65 54 61 6b 65 72 5c 53 65 74 74 4d 73 5c 47 65 6e 65 72 61 6c } //01 00 
		$a_01_6 = {4c 41 c2 a4 08 16 2a 2e c8 b0 61 43 14 9a 65 ea 87 8b 39 79 e6 74 4c 15 57 d2 d6 df 9b bb b5 31 } //00 00 
	condition:
		any of ($a_*)
 
}