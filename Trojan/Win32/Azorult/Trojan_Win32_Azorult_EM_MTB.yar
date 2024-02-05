
rule Trojan_Win32_Azorult_EM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {c1 e2 04 89 54 24 10 8b 44 24 24 01 44 24 10 8b 7c 24 18 8b ce c1 e9 05 03 cd 03 fe } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {31 7c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 18 8b 44 24 24 29 44 24 14 ff 4c 24 1c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 f3 0f 58 c8 0f 57 c0 f3 0f 2a c0 f3 0f 58 c8 0f 57 c0 } //02 00 
		$a_01_1 = {8b f9 2b f8 89 7c 24 40 8b 7c 24 58 8b 44 24 5c 8a 54 24 67 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 75 f4 8b 4d f0 8b c6 d3 e0 8b 4d fc 8b d6 c1 ea 05 03 45 d0 03 55 d4 03 ce 33 c1 33 c2 2b f8 89 55 f8 } //00 00 
	condition:
		any of ($a_*)
 
}