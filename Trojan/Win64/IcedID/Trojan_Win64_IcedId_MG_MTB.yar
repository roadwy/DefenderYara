
rule Trojan_Win64_IcedId_MG_MTB{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 0f af 0d 90 01 04 44 03 c0 48 8b 05 90 01 04 49 83 c3 04 44 89 05 90 01 04 41 8b d1 c1 ea 10 88 14 01 41 8b d1 8b 05 90 01 04 03 c6 c1 ea 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedId_MG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {41 4b 6f 73 75 47 55 70 } //01 00  AKosuGUp
		$a_01_2 = {41 5a 6c 52 64 55 59 62 56 4c 6e } //01 00  AZlRdUYbVLn
		$a_01_3 = {54 74 2e 64 6c 6c } //01 00  Tt.dll
		$a_01_4 = {42 41 79 58 66 63 44 6d 63 4b } //01 00  BAyXfcDmcK
		$a_01_5 = {43 66 4f 61 77 67 6f 6f 75 4a 66 } //00 00  CfOawgoouJf
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedId_MG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 08 8a 09 66 3b c0 74 00 88 08 48 8b 04 24 3a db 74 1a 4c 89 44 24 18 48 89 54 24 10 3a f6 74 17 48 8b 44 24 08 48 ff c0 3a c9 74 25 48 ff c0 48 89 04 24 3a e4 74 e9 } //05 00 
		$a_01_1 = {62 69 61 79 75 73 64 6a 61 73 64 75 67 61 79 73 68 67 64 6a 61 6b 73 61 } //00 00  biayusdjasdugayshgdjaksa
	condition:
		any of ($a_*)
 
}