
rule Trojan_Win32_Redline_ZYZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d 90 01 01 8d 45 90 01 01 33 4d 90 01 01 33 d2 33 4d 90 01 01 89 15 90 01 04 51 50 89 4d 90 01 01 e8 90 00 } //1
		$a_03_1 = {c1 e8 05 c7 05 90 01 08 89 45 08 8b 45 90 01 01 01 45 90 01 01 03 f3 33 75 90 01 01 8d 45 90 01 01 33 75 90 01 01 56 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}