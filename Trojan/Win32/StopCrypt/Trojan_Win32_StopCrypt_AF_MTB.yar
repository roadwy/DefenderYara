
rule Trojan_Win32_StopCrypt_AF_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 0c 37 c1 ee 05 03 75 ec 03 c3 33 c1 33 f0 89 45 0c 89 75 e8 } //2
		$a_01_1 = {8b 45 0c 83 6d fc 04 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}