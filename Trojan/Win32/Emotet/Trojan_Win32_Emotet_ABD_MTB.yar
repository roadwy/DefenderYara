
rule Trojan_Win32_Emotet_ABD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ABD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 35 74 6d 5f 70 37 53 55 68 49 43 39 6c 36 3f 50 68 28 2a 63 78 54 56 67 55 59 77 49 76 4b 4f 68 5e 31 59 5a 6e 58 33 42 31 64 65 77 62 35 4f 51 3c 4c 26 43 68 5e 5a 4d 73 2a 73 4e 63 5f 6c 61 73 67 74 39 4d 26 66 44 6b 74 6a 72 3e 78 33 2b 78 66 56 23 48 57 31 73 62 2b 51 68 39 50 66 73 3e 35 6a 32 75 41 42 6b } //00 00 
	condition:
		any of ($a_*)
 
}