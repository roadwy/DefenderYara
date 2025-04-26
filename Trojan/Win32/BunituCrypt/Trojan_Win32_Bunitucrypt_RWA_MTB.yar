
rule Trojan_Win32_Bunitucrypt_RWA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 [0-05] 0e 00 00 00 } //1
		$a_03_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 ?? ?? ?? ?? ?? 04 [0-0f] a1 ?? ?? ?? ?? 3b [0-19] 2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 } //1
		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RWA_MTB_4{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b ?? ?? 3b ?? ?? 0f } //1
		$a_03_1 = {8b d8 8b 45 ?? 03 ?? ?? 03 ?? ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 31 18 a1 ?? ?? ?? ?? 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}