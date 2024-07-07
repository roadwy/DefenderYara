
rule Trojan_Win32_Redline_ASAA_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 33 c0 33 db f6 17 80 2f 90 01 01 80 07 90 01 01 f6 2f 47 e2 90 00 } //1
		$a_03_1 = {8b 7d 08 33 c0 33 db f6 17 80 37 90 01 01 47 e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}