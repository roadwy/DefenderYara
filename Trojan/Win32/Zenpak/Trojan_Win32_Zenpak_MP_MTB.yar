
rule Trojan_Win32_Zenpak_MP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f9 60 68 54 b1 45 0d 76 ab a7 98 eb 01 d4 34 d5 5c 4f d7 64 41 3e 34 5e 34 b1 1c de 17 f0 05 76 } //01 00 
		$a_01_1 = {6c 40 72 4a 51 52 59 33 43 64 51 5f 45 69 56 62 69 61 4d 45 58 77 4b } //00 00  l@rJQRY3CdQ_EiVbiaMEXwK
	condition:
		any of ($a_*)
 
}