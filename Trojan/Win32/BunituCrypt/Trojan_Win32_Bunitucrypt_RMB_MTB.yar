
rule Trojan_Win32_Bunitucrypt_RMB_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 90 01 02 3b 90 01 02 0f 90 02 09 8b 90 01 02 8b 90 01 02 01 02 8b 90 01 02 03 90 01 02 03 90 01 02 8b 90 01 02 31 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bunitucrypt_RMB_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 99 52 50 8b 45 90 01 01 33 d2 3b 54 24 90 01 01 75 90 00 } //1
		$a_00_1 = {2d 00 10 00 00 83 c0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Bunitucrypt_RMB_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 0f 90 02 08 a1 90 01 04 03 05 90 01 04 2d 00 10 00 00 83 c0 04 90 00 } //1
		$a_03_1 = {8a a5 08 00 90 02 0a 0e 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}