
rule Trojan_Win64_REntS_SIBC_MTB{
	meta:
		description = "Trojan:Win64/REntS.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 65 61 6b 65 64 20 48 65 61 70 20 41 64 64 72 65 73 73 } //01 00 
		$a_03_1 = {44 8b da 48 85 c0 75 90 01 01 b8 90 01 04 eb 90 01 01 4c 8b d0 48 8b 81 90 01 04 48 d1 e8 4d 8d 42 90 01 01 4c 03 c0 4c 89 41 90 01 01 8b 41 90 01 01 85 c0 7f 90 01 01 45 85 db 74 90 01 01 ff c8 33 d2 89 41 90 01 01 41 8b c3 f7 f3 80 c2 90 01 01 44 8b d8 80 fa 90 01 01 7e 90 01 01 41 8a c1 34 90 01 01 c0 e0 90 01 01 04 90 01 01 02 d0 48 8b 41 90 01 01 88 10 48 ff 49 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}