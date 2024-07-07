
rule Trojan_Win64_Tedy_PABC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 68 59 00 66 4d c7 44 24 6c 53 54 5e 55 c7 44 24 70 4d 49 66 49 c7 44 24 74 43 49 4e 5f c7 44 24 78 57 09 08 66 c7 44 24 7c 54 4e 5e 56 c7 45 80 56 14 5e 56 66 c7 45 84 56 3a c7 45 c8 43 72 65 61 c7 45 cc 74 65 46 69 c7 45 d0 6c 65 4d 61 c7 45 d4 70 70 69 6e 66 c7 45 d8 67 41 c6 45 da 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}