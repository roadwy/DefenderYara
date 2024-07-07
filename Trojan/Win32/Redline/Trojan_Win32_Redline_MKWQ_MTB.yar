
rule Trojan_Win32_Redline_MKWQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 89 55 90 00 } //1
		$a_03_1 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 8b 55 90 01 01 33 55 90 01 01 89 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}