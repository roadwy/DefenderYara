
rule Trojan_Win32_Bunitucrypt_RTB_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 02 6a 00 e8 90 02 04 8b d8 83 c3 04 6a 00 e8 90 02 04 2b d8 01 90 02 05 83 90 02 05 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 90 02 0a 83 90 02 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RTB_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 90 01 01 c7 45 90 01 01 8a a5 08 00 8b 45 90 01 01 3b 45 90 01 01 73 90 01 01 e8 90 02 0e 8b 45 90 01 01 8b 55 90 01 01 01 10 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}