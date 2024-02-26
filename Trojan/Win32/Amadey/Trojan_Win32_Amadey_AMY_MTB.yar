
rule Trojan_Win32_Amadey_AMY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 f6 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 33 f1 3b d3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_AMY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 2b c6 57 3b f8 77 90 01 01 8d 04 3e 83 fb 10 89 85 90 01 04 8d 85 90 01 04 0f 43 85 90 01 04 03 f0 8d 85 90 01 04 50 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_AMY_MTB_3{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51 c7 84 24 18 02 00 00 84 82 10 45 c7 84 24 08 01 00 00 80 d9 0f 28 c7 84 24 20 01 00 00 5a 91 84 3c c7 84 24 ac 01 00 00 c2 99 3e 72 c7 84 24 e0 00 00 00 f4 09 87 1b c7 84 24 00 02 00 00 d9 b0 ba 48 c7 84 24 50 01 00 00 02 a6 fb 09 } //00 00 
	condition:
		any of ($a_*)
 
}