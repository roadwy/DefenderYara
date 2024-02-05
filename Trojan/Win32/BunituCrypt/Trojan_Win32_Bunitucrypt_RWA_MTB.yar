
rule Trojan_Win32_Bunitucrypt_RWA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 02 05 0e 00 00 00 90 00 } //01 00 
		$a_03_1 = {31 02 83 05 90 01 04 04 83 90 01 05 04 90 02 0f a1 90 01 04 3b 90 02 19 2d 00 10 00 00 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 90 01 04 3b 05 90 01 04 73 90 01 01 a1 90 01 04 8b 15 90 01 04 01 10 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 00 } //01 00 
		$a_03_1 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 90 01 01 e8 90 01 04 8b d8 83 c3 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 90 01 02 3b 90 01 02 0f 90 00 } //01 00 
		$a_03_1 = {8b d8 8b 45 90 01 01 03 90 01 02 03 90 01 02 03 d8 6a 90 01 01 e8 90 01 04 2b d8 a1 90 01 04 31 18 a1 90 01 04 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}