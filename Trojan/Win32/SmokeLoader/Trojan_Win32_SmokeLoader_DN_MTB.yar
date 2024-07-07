
rule Trojan_Win32_SmokeLoader_DN_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ce 89 4c 24 20 8b 4c 24 1c d3 ee 8b 4c 24 3c 8d 44 24 14 c7 05 90 02 04 ee 3d ea f4 89 74 24 14 e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}