
rule Trojan_Win32_Bunitucrypt_RTB_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 02 6a 00 e8 [0-04] 8b d8 83 c3 04 6a 00 e8 [0-04] 2b d8 01 [0-05] 83 [0-05] 04 } //1
		$a_03_1 = {2d 00 10 00 00 [0-0a] 83 [0-05] 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RTB_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? e8 [0-0e] 8b 45 ?? 8b 55 ?? 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}