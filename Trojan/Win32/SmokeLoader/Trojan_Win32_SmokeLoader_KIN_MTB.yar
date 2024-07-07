
rule Trojan_Win32_SmokeLoader_KIN_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f7 c1 ee 90 01 01 03 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 08 75 90 01 01 53 53 8d 4c 24 90 01 01 51 ff 15 90 01 04 8b 4c 24 90 01 01 33 ce 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 83 6c 24 90 01 02 8b 54 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}