
rule Trojan_Win32_Graftor_SIBC_MTB{
	meta:
		description = "Trojan:Win32/Graftor.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 69 63 65 44 6c 6c } //01 00 
		$a_03_1 = {33 ff 5b 8a 46 90 01 01 8a 0e d0 e0 02 46 90 01 01 6a 04 d0 e1 02 4e 90 01 01 d0 e0 02 46 90 01 01 0f be c9 d0 e0 02 46 90 01 01 03 cf c1 e1 90 01 01 0f be c0 8d 84 08 90 01 04 8b 4d 90 01 01 50 ff 75 90 01 01 e8 90 01 04 83 45 90 01 01 04 83 c7 90 01 01 83 c6 90 01 01 4b 75 90 00 } //01 00 
		$a_03_2 = {33 c0 39 44 24 0c 7e 90 01 01 56 8b 74 24 0c 8b d0 c1 fa 90 01 01 8a c8 8a 14 32 80 e1 90 01 01 d2 fa 8b 4c 24 08 80 e2 90 01 01 88 14 08 40 3b 44 24 10 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}