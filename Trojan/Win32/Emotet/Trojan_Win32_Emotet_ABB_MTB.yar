
rule Trojan_Win32_Emotet_ABB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 72 56 25 6c 67 30 39 6d 68 34 68 40 40 72 69 6c 74 70 5f 54 66 42 43 46 46 35 23 35 52 40 21 51 62 23 66 6f 61 78 21 55 59 29 4e 3e 6b 79 31 4d 61 53 70 48 2a 56 3f 4e 6a 6d 43 38 28 43 33 34 23 42 38 } //01 00 
		$a_01_1 = {47 21 66 40 29 34 64 56 26 2a 4d 3c 58 6a 63 67 2a 79 78 74 6e 23 2a 24 38 36 70 57 5a 39 48 55 21 28 56 4b 67 4c 7a 54 30 51 34 57 } //00 00 
	condition:
		any of ($a_*)
 
}