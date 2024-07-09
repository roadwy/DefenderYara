
rule Trojan_Win32_Bunitucrypt_RMB_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b ?? ?? 3b ?? ?? 0f [0-09] 8b ?? ?? 8b ?? ?? 01 02 8b ?? ?? 03 ?? ?? 03 ?? ?? 8b ?? ?? 31 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMB_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 99 52 50 8b 45 ?? 33 d2 3b 54 24 ?? 75 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMB_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f [0-08] a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2d 00 10 00 00 83 c0 04 } //1
		$a_03_1 = {8a a5 08 00 [0-0a] 0e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}