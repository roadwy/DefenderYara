
rule Trojan_Win32_Redline_MVL_MTB{
	meta:
		description = "Trojan:Win32/Redline.MVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 c7 85 90 01 08 8b 45 90 01 01 01 85 90 01 04 8b 45 f4 90 00 } //1
		$a_03_1 = {d3 ea 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}