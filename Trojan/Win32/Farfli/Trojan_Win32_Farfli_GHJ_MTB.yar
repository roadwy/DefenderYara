
rule Trojan_Win32_Farfli_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 0f be 4c 05 f0 8b 55 e4 03 55 d8 0f b6 02 33 c1 8b 4d e4 03 4d d8 88 01 8b 45 e0 83 c0 01 89 45 e0 eb 9d } //01 00 
		$a_01_1 = {43 3a 5c 44 65 6c 2e 62 61 74 } //01 00 
		$a_01_2 = {5c 4b 4c 53 4e 49 46 2e 6b 65 79 } //00 00 
	condition:
		any of ($a_*)
 
}