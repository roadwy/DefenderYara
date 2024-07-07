
rule Trojan_Win32_Staser_RK_MTB{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 b8 01 00 00 00 59 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 06 58 ff 75 08 57 90 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RK_MTB_3{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec ff 15 d8 63 65 00 6a ff 6a 00 6a 00 ff 15 c8 66 65 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RK_MTB_4{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 14 50 ff 15 78 66 65 00 6a 00 6a 00 ff 15 9c 66 65 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Staser_RK_MTB_5{
	meta:
		description = "Trojan:Win32/Staser.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 f6 c4 01 b8 0c 01 0b 80 ff 35 3c 44 08 01 ff 15 b0 f3 46 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}