
rule Trojan_Win32_CryptInject_CD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 73 6f 63 68 76 73 74 2e 62 61 74 } //01 00 
		$a_81_1 = {48 45 42 45 43 41 40 43 48 49 4e 41 2e 43 4f 4d } //01 00 
		$a_81_2 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_CD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {7e 08 81 f9 d0 a6 8f 34 75 08 40 3d aa 8f e0 14 7c e9 } //01 00 
		$a_02_1 = {81 fe 01 3f 14 22 7c cd a1 90 01 04 8b f7 05 3b 2d 0b 00 a3 90 01 04 81 fe 89 62 65 00 75 10 68 90 01 04 ff 15 90 01 04 a3 90 01 04 46 81 fe 56 d0 66 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}