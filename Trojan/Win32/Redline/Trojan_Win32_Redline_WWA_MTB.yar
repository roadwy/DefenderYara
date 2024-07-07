
rule Trojan_Win32_Redline_WWA_MTB{
	meta:
		description = "Trojan:Win32/Redline.WWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 51 8d 45 90 01 01 50 c7 05 90 01 08 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 2b f8 89 45 90 01 01 8b c7 90 00 } //1
		$a_03_1 = {31 08 83 c5 70 c9 90 0a 33 00 b8 90 01 04 f7 65 90 01 01 8b 45 90 01 01 81 6d 90 01 05 81 6d 90 01 05 81 45 90 01 05 81 6d 90 01 05 8b 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}