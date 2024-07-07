
rule Trojan_Win32_Redline_AVX_MTB{
	meta:
		description = "Trojan:Win32/Redline.AVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c6 50 8d 45 90 01 01 50 c7 05 90 01 08 e8 03 f9 ff ff 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 2b f8 89 45 90 01 01 8b c7 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 0d 90 01 05 8b c7 90 00 } //1
		$a_00_1 = {31 08 83 c5 70 c9 c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}